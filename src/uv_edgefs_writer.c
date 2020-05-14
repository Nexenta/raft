#include <errno.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <uv.h>
#include <raft.h>

#include "err.h"
#include "uv_edgefs_writer.h"

/* Callback run after writeWorkCb has returned. It normally invokes the write
 * request callback. */
static void
writeAfterWorkCb(uv_work_t *work, int status)
{
    struct UvWriterReq *req; /* Write file request object */

    assert(status == 0); /* We don't cancel worker requests */

    req = work->data;

    /* If we were closed, let's mark the request as canceled,
     * regardless of the actual outcome.
     */
    if (req->writer->closing) {
        ErrMsgPrintf(req->errmsg, "canceled");
        req->status = RAFT_CANCELED;
    }

    req->cb(req, req->status);
}

static void skip_free(void *ptr) {}

/* Run blocking syscalls involved in a file write request. */
static void
writeWorkCb(uv_work_t *work)
{
    struct UvWriterReq *req; /* Write file request object */
    struct uvFile *f;        /* File object */
    int rv;

    req = work->data;
        req->status = 0;
    f = req->writer->fd;

    uint64_t offset = req->offset;
    unsigned i;

    for (i = 0; i < req->bufs_count; i++) {
        size_t nb_written = 0;
        ccow_fsio_write_free_set(f->file, skip_free);
        rv = ccow_fsio_write(f->file, offset, req->bufs[i].len,
            (void *)req->bufs[i].base, &nb_written);
        if (rv) {
            req->status = RAFT_IOERR;
        } else {
            if (nb_written != req->bufs[i].len) {
                ErrMsgPrintf(req->errmsg,
                    "short write: %zu bytes instead of %zu",
                    nb_written, req->len);
                req->status = RAFT_NOSPACE;
                return;
            }
        }

        offset += nb_written;
        req->offset = offset;
    }
}

int UvWriterInit(struct UvWriter *w,
                 struct uv_loop_s *loop,
                 uvFd fd,
                 bool direct /* Whether to use direct I/O */,
                 bool async /* Whether async I/O is available */,
                 unsigned max_concurrent_writes,
                 char *errmsg)
{
    void *data = w->data;
    int rv = 0;

    memset(w, 0, sizeof *w);
    w->data = data;
    w->loop = loop;
    w->fd = fd;
    w->async = async;
    w->close_cb = NULL;
    w->closing = false;
    w->errmsg = errmsg;

    return rv;
}

static void
closeAfterWorkCb(uv_work_t *work, int status)
{
    struct UvWriter *w;

    w = work->data;
    w->close_cb(w);
    free(work);
}

static void
closeWorkCb(uv_work_t *work)
{
    struct UvWriter *w;

    w = work->data;
    if (w->fd->file) {
        ccow_fsio_close(w->fd->file);
        w->fd->file = NULL;
    }
}

void UvWriterClose(struct UvWriter *w, UvWriterCloseCb cb)
{
    assert(w->fd != NULL);
    assert(!w->closing);

    w->closing = true;
    w->close_cb = cb;

    if (!cb) {
        if (w->fd->file) {
            ccow_fsio_close(w->fd->file);
            w->fd->file = NULL;
            return;
        }
    }

    uv_work_t *req = calloc(1, sizeof(req));
    req->data = w;
    int rv = uv_queue_work(w->loop, req, closeWorkCb, closeAfterWorkCb);
    if (rv != 0) {
        /* UNTESTED: with the current libuv implementation this can't fail. */
        return;
    }
}

/* Return the total lengths of the given buffers. */
static size_t lenOfBufs(const uv_buf_t bufs[], unsigned n)
{
    size_t len = 0;
    unsigned i;
    for (i = 0; i < n; i++) {
        len += bufs[i].len;
    }
    return len;
}

int UvWriterSubmit(struct UvWriter *w,
                   struct UvWriterReq *req,
                   const uv_buf_t bufs[],
                   unsigned n,
                   size_t offset,
                   UvWriterReqCb cb)
{
    int rv = 0;
    uv_buf_t *io_bufs = (uv_buf_t *)bufs;
    assert(!w->closing);

    assert(w->fd != NULL);
    assert(req != NULL);
    assert(bufs != NULL);
    assert(n > 0);

    req->writer = w;
    req->len = lenOfBufs(bufs, n);
    req->status = -1;
    req->work.data = req;
    req->cb = cb;
    req->bufs = io_bufs;
    req->bufs_count = n;
    req->offset = offset;
    memset(req->errmsg, 0, sizeof req->errmsg);

    rv = uv_queue_work(w->loop, &req->work, writeWorkCb, writeAfterWorkCb);
    if (rv != 0) {
        /* UNTESTED: with the current libuv implementation this can't fail. */
        req->work.data = NULL;
        rv = RAFT_IOERR;
    }

    return rv;
}
