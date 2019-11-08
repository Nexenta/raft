#include <errno.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <uv.h>

#include "uv_ccowfsio_file.h"

extern Logger fsio_lg;
static int ccowfsio_init = 0;

extern int
ccow_fsio_find_export(char *cid, size_t cid_size, char *tid, size_t tid_size,
    char *bid, size_t bid_size, ci_t ** out_ci);

ci_t *
findFSExportByDir(char *dir, inode_t *subdir_inode)
{
	char cid[2048], tid[2048], bid[2048], subdir[2048];
	size_t cid_size, tid_size, bid_size;
	ci_t *ci = NULL;
	int err;

	*cid = *tid = *bid = *subdir = 0;
	*subdir_inode = 0;

	if (!ccowfsio_init) {
		err = ccow_fsio_init();
		if (err)
			return NULL;
		ccowfsio_init = 1;
	}

	if (sscanf(dir, "%2047[^/]/%2047[^/]/%2047[^/]/%2047[^\n]",
		    cid, tid, bid, subdir) < 3) {
		return NULL;
	}
	cid_size = strlen(cid) + 1;
	tid_size = strlen(tid) + 1;
	bid_size = strlen(bid) + 1;

	ccow_fsio_find_export(cid, cid_size, tid, tid_size, bid, bid_size, &ci);
	if (!ci) {
		ci = ccow_fsio_ci_alloc();
		if (!ci) {
			return NULL;
		}

		char path[PATH_MAX];
		snprintf(path, sizeof(path), "%s/etc/ccow/ccow.json", nedge_path());

		err = ccow_fsio_create_export(ci, "cltest/test/test", path,
		    4096, NULL, NULL);
		if (err) {
			ccow_fsio_ci_free(ci);
			return NULL;
		}

		if (*subdir) {
			err = ccow_fsio_mkdir(ci, CCOW_FSIO_ROOT_INODE, subdir,
			    S_IFDIR | 0750, 0, 0, subdir_inode);
			if (err && err != EEXIST) {
				ccow_fsio_delete_export(ci);
				ccow_fsio_ci_free(ci);
				return NULL;
			}
		} else
			*subdir_inode = CCOW_FSIO_ROOT_INODE;
	} else {
		if (*subdir) {
			memmove(subdir+1, subdir, strlen(subdir)+1); *subdir = '/';
			err = ccow_fsio_find(ci, subdir, subdir_inode);
			if (err) {
				return ci;
			}
		} else
			*subdir_inode = CCOW_FSIO_ROOT_INODE;
	}

	return ci;
}

int uvFileInit(struct uvFile *f,
               struct uv_loop_s *loop,
               bool direct,
               bool async,
               char *errmsg)
{
	f->loop = loop;
	f->direct = direct;
	f->async = async;
	f->closing = false;
	f->close_cb = NULL;

	return 0;
}

static void
createAfterWorkCb(uv_work_t *work, int status)
{
	struct uvFileCreate *req;
	struct uvFile *f;

	req = work->data;
	assert(req != NULL);
	f = req->file;

	/* If we were closed, abort here. */
	if (f->closing) {
		uvTryUnlinkFile(req->dir, req->filename);
		uvErrMsgPrintf(req->errmsg, "canceled");
		req->status = UV__CANCELED;
	}

	req->cb(req, req->status, req->errmsg);
}

static void skip_free(void *ptr) {}

/* Run blocking syscalls involved in file creation (e.g. posix_fallocate()). */
static void
createWorkCb(uv_work_t *work)
{
	struct uvFileCreate *req; /* Create file request object */
	struct uvFile *f;         /* File handle */
	int err;

	req = work->data;
	f = req->file;

	if (f->closing) {
		uvTryUnlinkFile(req->dir, req->filename);
		uvErrMsgPrintf(req->errmsg, "canceled");
		req->status = UV__CANCELED;
		return;
	}

	err = ccow_fsio_touch(f->ci, f->subdir_inode, req->filename,
	    0600, 0, 0, &f->inode);
	if (err && err != EEXIST) {
		uvErrMsgPrintf(req->errmsg, "touch err %d", err);
		req->status = UV__ERROR;
		return;
	}

	err = ccow_fsio_openi(f->ci, f->inode, &f->file, O_RDWR);
	if (err) {
		uvErrMsgPrintf(req->errmsg, "openi err %d", err);
		req->status = UV__ERROR;
		return;
	}

	ccow_fsio_write_free_set(f->file, skip_free);

	static char b;
	size_t write_amount = 0;
	err = ccow_fsio_write(f->file, req->size - 1, 1, (void *)&b, &write_amount);
	if (err || write_amount != 1) {
		uvErrMsgPrintf(req->errmsg, "write err %d", err);
		req->status = UV__ERROR;
		return;
	}
}

int
uvFileCreate(struct uvFile *f,
             struct uvFileCreate *req,
             uvDir dir,
             uvFilename filename,
             size_t size,
             unsigned max_n_writes,
             uvFileCreateCb cb,
             char *errmsg)
{
	int err;

	req->file = f;
	req->cb = cb;
	strcpy(req->dir, dir);
	strcpy(req->filename, filename);
	req->size = size;
	req->status = 0;
	req->work.data = req;

	if (strchr(filename, '/')) {
		uvErrMsgPrintf(errmsg, "open: No such file or directory");
		req->status = UV__NOENT;
		return req->status;
	}

	f->ci = findFSExportByDir(req->dir, &f->subdir_inode);
	/* ENOENT case for parent dir */
	if (f->subdir_inode == 0) {
		uvErrMsgPrintf(errmsg, "open: No such file or directory");
		req->status = UV__NOENT;
		return req->status;
	}
	if (!f->ci) {
		uvErrMsgPrintf(errmsg, "fsio init err");
		req->status = UV__ERROR;
		return req->status;
	}

	inode_t fi;
	err = ccow_fsio_lookup(f->ci, f->subdir_inode, filename, &fi);
	if (err != ENOENT) {
		uvErrMsgPrintf(errmsg, "open: File exists");
		req->status = UV__ERROR;
		return req->status;
	}

	err = uv_queue_work(f->loop, &req->work, createWorkCb, createAfterWorkCb);
	if (err) {
		/* UNTESTED: with the current libuv implementation this can't fail. */
		uvErrMsgPrintf(errmsg, "uv_queue_work: %s", uv_strerror(uv_last_error(f->loop)));
		req->status = UV__ERROR;
		return req->status;
	}


	return 0;
}

/* Callback run after writeWorkCb has returned. It normally invokes the write
 * request callback. */
static void
writeAfterWorkCb(uv_work_t *work, int status)
{
	struct uvFileWrite *req; /* Write file request object */
	struct uvFile *f;

	assert(status == 0); /* We don't cancel worker requests */

	req = work->data;
	f = req->file;

	/* If we were closed, let's mark the request as canceled, regardless of the
	 * actual outcome. */
	if (f->closing) {
		uvErrMsgPrintf(req->errmsg, "canceled");
		req->status = UV__CANCELED;
	}

	req->cb(req, req->status, req->errmsg);
}

/* Run blocking syscalls involved in a file write request. */
static void
writeWorkCb(uv_work_t *work)
{
	struct uvFileWrite *req; /* Write file request object */
	struct uvFile *f;        /* File object */
	int err;

	req = work->data;
	f = req->file;

	uint64_t offset = req->offset;
	unsigned i;
	for (i = 0; i < req->bufs_count; i++) {
		size_t nb_written = 0;
		err = ccow_fsio_write(f->file, offset, req->bufs[i].len,
		    (void *)req->bufs[i].base, &nb_written);
		if (err || nb_written != req->bufs[i].len) {
			uvErrMsgPrintf(req->errmsg, "write err %d", err);
			req->status = UV__ERROR;
			return;
		}

		offset += nb_written;
	}
}

int
uvFileWrite(struct uvFile *f,
            struct uvFileWrite *req,
            const uv_buf_t bufs[],
            unsigned n,
            size_t offset,
            uvFileWriteCb cb,
            char *errmsg)
{
	int rv;

	assert(!f->closing);
	assert(!f->async);

	req->file = f;
	req->work.data = req;
	req->bufs = (uv_buf_t*)bufs;
	req->bufs_count = n;
	req->offset = offset;
	req->cb = cb;

	rv = uv_queue_work(f->loop, &req->work, writeWorkCb, writeAfterWorkCb);
	if (rv != 0) {
		/* UNTESTED: with the current libuv implementation this can't fail. */
		uvErrMsgPrintf(errmsg, "uv_queue_work: %s", uv_strerror(uv_last_error(f->loop)));
		return UV__ERROR;
	}
	return rv;
}

bool
uvFileIsOpen(struct uvFile *f)
{
	return !f->closing;
}

static void
closeAfterWorkCb(uv_work_t *work, int status)
{
	struct uvFile *f;

	f = work->data;
	f->close_cb(f);
	free(work);
}

/* Run blocking syscalls involved in file creation (e.g. posix_fallocate()). */
static void
closeWorkCb(uv_work_t *work)
{
	struct uvFile *f;

	f = work->data;
	ccow_fsio_close(f->file);
}

void
uvFileClose(struct uvFile *f, uvFileCloseCb cb)
{
	f->closing = true;
	f->close_cb = cb;

	if (f->file) {
		if (!cb) {
			ccow_fsio_close(f->file);
			return;
		}

		uv_work_t *req = calloc(1, sizeof(req));
		req->data = f;
		int err = uv_queue_work(f->loop, req, closeWorkCb, closeAfterWorkCb);
		if (err != 0) {
			/* UNTESTED: with the current libuv implementation this can't fail. */
			return;
		}
	} else {
		if (cb) {
			cb(NULL);
		}
	}
}
