#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "assert.h"
#include "uv_error.h"
#include "uv_os.h"

/* Default permissions when creating a directory. */
#define DEFAULT_DIR_PERM 0700

void uvJoin(const uvDir dir, const uvFilename filename, uvPath path)
{
    strcpy(path, dir);
    strcat(path, "/");
    strcat(path, filename);
}

#if UV_CCOWFSIO_ENABLED
#include "uv_ccowfsio_file.h"
int uvEnsureDir(const uvDir dir, char *errmsg)
{
    char dpath[UV__PATH_MAX_LEN];
    struct stat sb;
    int err;

    /* Check that the given path doesn't exceed our static buffer limit */
    assert(strnlen(dir, UV__DIR_MAX_LEN + 1) <= UV__DIR_MAX_LEN);

    /* Make sure that dir with ccow hierarchy does not exist */
    err = stat(dir, &sb);
    if (err == 0 && (sb.st_mode & S_IFMT) != S_IFDIR) {
	    uvErrMsgPrintf(errmsg, "%s", strerror(ENOTDIR));
	    return UV__ERROR;
    }

    /* If dir with ccow hierarchy exists, deny further op */
    if (err == 0) {
            uvErrMsgSys(errmsg, stat, EACCES);
	    return UV__ERROR;
    }

    if (err < 0 && errno == EACCES) {
        uvErrMsgSys(errmsg, stat, EACCES);
        return UV__ERROR;
    }

    inode_t di;
    char *subdir = NULL, *root = NULL, *p;
    strcpy(dpath, dir);
    p = strrchr(dpath, '/');
    if (p) {
	*p = 0;
        subdir = p+1;
    }
    ci_t *ci = findFSExportByDir((char*)dpath, &di);
    if (!ci) {
        uvErrMsgSys(errmsg, mkdir, EACCES);
        return UV__ERROR;
    }
    if (di == 0) {
        uvErrMsgSys(errmsg, stat, EACCES);
        return UV__ERROR;
    }

    strcpy(dpath, dir);
    /* Get tenant */
    p = strchr(dpath, '/');
    /* Get bucket */
    if (p) {
		p = strchr(p+1,'/');
    }
    /* Get root */
    if (p) {
		root = strchr(p+1,'/');
    }
    p = strrchr(dpath, '/');
    if (p) {
        subdir = p+1;
    }
    if (subdir) {
	inode_t ino;
	/* Search the entire path starting from root */
	assert(root[0] == '/');
	int err = ccow_fsio_find(ci, root, &ino);
	if (err != 0 && err == ENOENT) {
		err = ccow_fsio_mkdir(ci, di, subdir, DEFAULT_DIR_PERM,
				geteuid(), getegid(), NULL);
		if (err) {
			uvErrMsgSys(errmsg, mkdir, ENOTDIR);
			return UV__ERROR;
		}
	} else if (err == 0) {
		err = uvCheckAccess(ci, ino);
		if (err) {
			uvErrMsgSys(errmsg, stat, EACCES);
			return UV__ERROR;
		}
	}

    }
    return 0;
}

int uvSyncDir(const uvDir dir, char *errmsg)
{
    char dpath[UV__PATH_MAX_LEN];
    int err;

    strcpy(dpath, dir);
    char *subdir = strrchr(dpath, '/');
    inode_t di;

    ci_t *ci = findFSExportByDir((char*)dpath, &di);
    if (!ci) {
        uvErrMsgSys(errmsg, open, ENOENT);
        return UV__ERROR;
    }
    if (di == 0) {
        uvErrMsgSys(errmsg, stat, EACCES);
        return UV__ERROR;
    }
    if (subdir) {
	ccow_fsio_file_t *file;
	int err = ccow_fsio_open(ci, subdir, &file, O_RDONLY | O_DIRECTORY);
	if (err == 0) {
		err = ccow_fsio_flush(file);
		ccow_fsio_close(file);
		if (err) {
			uvErrMsgSys(errmsg, sync, EIO);
			return UV__ERROR;
		}
	}

    }
    return 0;
}

struct ccow_dir_data {
	ci_t *ci;
	struct dirent **dir_ents;
	int dir_count;
	uv_cond_t wait_cond;
	uv_mutex_t wait_mutex;
};

static int
list_cb(inode_t parent, fsio_dir_entry *dir_entry, uint64_t count, void *ptr)
{
	int err = 0;
	uint64_t i;
	struct ccow_dir_data *dirp = ptr;
	assert (dirp != NULL);

	if (dirp->dir_ents) {
		dirp->dir_ents = reallocarray(dirp->dir_ents,
				count + dirp->dir_count,
				sizeof (struct dirent *));
	} else {
		dirp->dir_ents = calloc(count + dirp->dir_count,
				sizeof (struct dirent *));
	}
	if (dirp->dir_ents == NULL) {
		err = 1;
		goto _out;
	}

	int idx = dirp->dir_count;
	for (i = 0; i < count; i++) {
		size_t len;
		dirp->dir_ents[idx] = calloc(1, sizeof (struct dirent));
		if (dirp->dir_ents[idx] == NULL) {
			err = 1;
			break;
		}

		dirp->dir_ents[idx]->d_ino = dir_entry[i].inode;
		len = strlen(dir_entry[i].name) > 255 ?
			255 : strlen(dir_entry[i].name);
		dirp->dir_ents[idx]->d_reclen = len;
		strncpy(dirp->dir_ents[idx]->d_name, dir_entry[i].name, len);
		dirp->dir_ents[idx]->d_type = DT_UNKNOWN;
		if (INODE_IS_DIR(dir_entry[i].inode))
			dirp->dir_ents[idx]->d_type = DT_DIR;
		else if (INODE_IS_FILE(dir_entry[i].inode))
			dirp->dir_ents[idx]->d_type = DT_REG;
		else if (INODE_IS_SYMLINK(dir_entry[i].inode))
			dirp->dir_ents[idx]->d_type = DT_LNK;
		dirp->dir_count++;
		idx++;
	}

_out:
	uv_cond_signal(&dirp->wait_cond);
	return err;
}

int uvScanDir(const uvDir dir,
              struct dirent ***entries,
              int *n_entries,
              char *errmsg)
{
    inode_t di;
    int err = 0;
    bool eof = false;
    struct ccow_dir_data dir_info;
    char *start = NULL;

    ci_t *ci = findFSExportByDir((char*)dir, &di);
    if (!ci || di == 0)
        return UV__ERROR;

    memset(&dir_info, 0, sizeof dir_info);
    uv_cond_init(&dir_info.wait_cond);
    uv_mutex_init(&dir_info.wait_mutex);

    while (err == 0 && !eof) {
	    start = dir_info.dir_count ?
		    dir_info.dir_ents[dir_info.dir_count - 1]->d_name : NULL;
	    err = ccow_fsio_readdir_cb4(ci, di, list_cb, start,
			    &dir_info, &eof);
	    if (err == 0 && !eof) {
		    uv_mutex_lock(&dir_info.wait_mutex);
		    uv_cond_wait(&dir_info.wait_cond, &dir_info.wait_mutex);
		    uv_mutex_unlock(&dir_info.wait_mutex);
	    }
    }
    uv_cond_destroy(&dir_info.wait_cond);
    uv_mutex_destroy(&dir_info.wait_mutex);
    *entries = dir_info.dir_ents;
    *n_entries = dir_info.dir_count;
    return err ? UV__ERROR : 0;
}

static void skip_free(void *ptr) {}

int uvOpenFile(const uvDir dir,
               const uvFilename filename,
               int flags,
               uvFd *fd,
               char *errmsg)
{
    int err;
    //struct uvFile *f = raft_calloc(1, sizeof(struct uvFile));
    struct uvFile *f = calloc(1, sizeof(struct uvFile));
    if (!f) {
        uvErrMsgSys(errmsg, open, ENOMEM);
        return UV__ERROR;
    }

    f->ci = findFSExportByDir((char*)dir, &f->subdir_inode);
    if (!f->ci) {
        uvErrMsgSys(errmsg, open, EACCES);
        free(f);
        return UV__ERROR;
    }
    if (f->subdir_inode == 0) {
        uvErrMsgSys(errmsg, open, EACCES);
        free(f);
        return UV__NOENT;
    }

    err = uvCheckAccess(f->ci, f->subdir_inode);

    if (flags & O_CREAT) {
	if (err) {
		uvErrMsgSys(errmsg, open, err);
                free(f);
                return UV__ERROR;
	}
        err = ccow_fsio_touch(f->ci, f->subdir_inode, (char*)filename,
            0600, geteuid(), getegid(), &f->inode);
        if (err && err != EEXIST) {
            uvErrMsgPrintf(errmsg, "touch err %d", err);
            free(f);
            return UV__ERROR;
        }
    } else {
	if (err == EACCES) {
		uvErrMsgSys(errmsg, open, err);
                free(f);
                return UV__ERROR;
	}
        uvPath path;
	char *root = NULL, *p;
	/* Get tenant */
	p = strchr(dir, '/');
	/* Get bucket */
	if (p)
		p = strchr(p+1,'/');
	/* Get root */
	if (p)
		root = strchr(p+1,'/');
        uvJoin(root, filename, path);

        err = ccow_fsio_find(f->ci, path, &f->inode);
        if (err) {
            if (err == ENOENT) {
		uvErrMsgSys(errmsg, open, ENOENT);
                free(f);
                return UV__NOENT;
            }
            uvErrMsgPrintf(errmsg, "open: err %d", err);
            free(f);
            return UV__ERROR;
        }
    }

    err = ccow_fsio_openi(f->ci, f->inode, &f->file, flags);
    if (err) {
        uvErrMsgPrintf(errmsg, "openi err %d", err);
        free(f);
        return UV__ERROR;
    }

    ccow_fsio_write_free_set(f->file, skip_free);

    *fd = f;
    return 0;
}

int uvCloseFile(uvFd fd)
{
    struct uvFile *f = fd;
    int err = ccow_fsio_close(f->file);
    free(f);
    return err ? UV__ERROR : 0;
}

int uvStatFile(const uvDir dir,
               const uvFilename filename,
               struct stat *sb,
               char *errmsg)
{
    inode_t di;
    ci_t *ci = findFSExportByDir((char*)dir, &di);
    if (!ci || di == 0)
        return UV__ERROR;
    int err;
    inode_t ino;
    err = ccow_fsio_lookup(ci, di, (char*)filename, &ino);
    if (err)
        return err == ENOENT ? UV__NOENT : UV__ERROR;
    err = ccow_fsio_get_file_stat(ci, ino, sb);
    return err ? UV__ERROR : 0;
}

int uvUnlinkFile(const char *dir, const char *filename, char *errmsg)
{
    inode_t di;
    ci_t *ci = findFSExportByDir((char*)dir, &di);
    if (!ci || di == 0)
        return UV__ERROR;
    return ccow_fsio_delete(ci, di, (char*)filename);
}

int uvFtruncate(uvFd fd, off_t length)
{
    /* FIXME: missing ccow_fsio_truncate() support
    struct uvFile *f = fd;
    */
    return 0;
}

int uvFsync(uvFd fd)
{
    struct uvFile *f = fd;
    int err = ccow_fsio_flush(f->file);
    return err ? UV__ERROR : 0;
}

int uvRenameFile(const uvDir dir,
                 const uvFilename filename1,
                 const uvFilename filename2,
                 char *errmsg)
{
    inode_t di;
    ci_t *ci = findFSExportByDir((char*)dir, &di);
    if (!ci || di == 0)
        return UV__ERROR;
    int err = ccow_fsio_move(ci, di, (char *)filename1, di, (char *)filename2);
    return err ? UV__ERROR : 0;
}

int uvReadFully(const uvFd fd, void *buf, const size_t n, char *errmsg)
{
    struct uvFile *f = fd;
    size_t read_amount;
    int eof;
    int err = ccow_fsio_read(f->file, f->offset, n, buf, &read_amount, &eof);
    if (err) {
        uvErrMsgSys(errmsg, read, err);
        return UV__ERROR;
    }
    if (read_amount < n) {
        uvErrMsgPrintf(errmsg, "short read: %d bytes instead of %ld", (int)read_amount, n);
        return UV__NODATA;
    }
    f->offset += read_amount;
    return 0;
}

int uvWriteFully(const uvFd fd, void *buf, const size_t n, char *errmsg)
{
    struct uvFile *f = fd;
    size_t write_amount;
    int err = ccow_fsio_write(f->file, f->offset, n, buf, &write_amount);
    if (err) {
        uvErrMsgSys(errmsg, write, err);
        return UV__ERROR;
    }
    if (write_amount < n) {
        uvErrMsgPrintf(errmsg, "short write: %d bytes instead of %ld", (int)write_amount, n);
        return UV__NODATA;
    }
    f->offset += write_amount;
    return 0;
}

#if defined(UV_CCOWFSIO_ENABLED)
off_t uvLseek(uvFd fd, off_t offset, int whence)
{
    struct uvFile *f = fd;
    if (whence == SEEK_SET) {
        f->offset = offset;
        return offset;
    } else if (whence == SEEK_CUR) {
        f->offset += offset;
        return f->offset;
    } else if (whence == SEEK_END) {
        struct stat stat;
        int err = ccow_fsio_get_file_stat(f->ci, f->inode, &stat);
        if (err)
            return (off_t) -1;
        f->offset = stat.st_size + offset;
    } else
        assert(0);
    return f->offset;
}
#endif /* !UV_CCOWFSIO_ENABLED */

ssize_t uvWritev(uvFd fd, const struct iovec *iov, int iovcnt)
{
    int err;
    size_t nb_written, io_amount = 0;
    struct uvFile *f = fd;
    for (int i = 0; i < iovcnt; i++) {
        err = ccow_fsio_write(f->file, f->offset,
            iov[i].iov_len, iov[i].iov_base, &nb_written);
        if (err) {
            return UV__ERROR;
        }

        if (nb_written == 0) {
            break;
        }

        io_amount += nb_written;
        f->offset += nb_written;
    }
    return io_amount;
}
#else
int uvEnsureDir(const uvDir dir, char *errmsg)
{
    struct stat sb;
    int rv;

    /* Check that the given path doesn't exceed our static buffer limit */
    assert(strnlen(dir, UV__DIR_MAX_LEN + 1) <= UV__DIR_MAX_LEN);

    /* Make sure we have a directory we can write into. */
    rv = stat(dir, &sb);
    if (rv == -1) {
        if (errno == ENOENT) {
            rv = mkdir(dir, DEFAULT_DIR_PERM);
            if (rv != 0) {
                uvErrMsgSys(errmsg, mkdir, errno);
                return UV__ERROR;
            }
        } else {
            uvErrMsgSys(errmsg, stat, errno);
            return UV__ERROR;
        }
    } else if ((sb.st_mode & S_IFMT) != S_IFDIR) {
        uvErrMsgPrintf(errmsg, "%s", strerror(ENOTDIR));
        return UV__ERROR;
    }

    return 0;
}

int uvSyncDir(const uvDir dir, char *errmsg)
{
    int fd;
    int rv;
    fd = open(dir, O_RDONLY | O_DIRECTORY);
    if (fd == -1) {
        uvErrMsgSys(errmsg, open, errno);
        return UV__ERROR;
    }
    rv = fsync(fd);
    close(fd);
    if (rv == -1) {
        uvErrMsgSys(errmsg, fsync, errno);
        return UV__ERROR;
    }
    return 0;
}

int uvScanDir(const uvDir dir,
              struct dirent ***entries,
              int *n_entries,
              char *errmsg)
{
    int rv;
    rv = scandir(dir, entries, NULL, alphasort);
    if (rv == -1) {
        uvErrMsgSys(errmsg, scandir, errno);
        return UV__ERROR;
    }
    *n_entries = rv;
    return 0;
}

int uvOpenFile(const uvDir dir,
               const uvFilename filename,
               int flags,
               uvFd *fd,
               char *errmsg)
{
    uvPath path;
    uvJoin(dir, filename, path);
    *fd = open(path, flags, S_IRUSR | S_IWUSR);
    if (*fd == -1) {
        uvErrMsgSys(errmsg, open, errno);
        return errno == ENOENT ? UV__NOENT : UV__ERROR;
    }
    return 0;
}

int uvCloseFile(uvFd fd)
{
    return close(fd);
}

int uvStatFile(const uvDir dir,
               const uvFilename filename,
               struct stat *sb,
               char *errmsg)
{
    uvPath path;
    int rv;
    uvJoin(dir, filename, path);
    rv = stat(path, sb);
    if (rv == -1) {
        uvErrMsgSys(errmsg, stat, errno);
        return errno == ENOENT ? UV__NOENT : UV__ERROR;
    }
    return 0;
}

int uvUnlinkFile(const char *dir, const char *filename, char *errmsg)
{
    uvPath path;
    int rv;
    uvJoin(dir, filename, path);
    rv = unlink(path);
    if (rv == -1) {
        uvErrMsgSys(errmsg, unlink, errno);
        return UV__ERROR;
    }
    return 0;
}

int uvFtruncate(uvFd fd, off_t length)
{
	return ftruncate(fd, length);
}

int uvFsync(uvFd fd)
{
	return fsync(fd);
}

int uvRenameFile(const uvDir dir,
                 const uvFilename filename1,
                 const uvFilename filename2,
                 char *errmsg)
{
    uvPath path1;
    uvPath path2;
    int rv;
    uvJoin(dir, filename1, path1);
    uvJoin(dir, filename2, path2);
    /* TODO: double check that filename2 does not exist. */
    rv = rename(path1, path2);
    if (rv == -1) {
        uvErrMsgSys(errmsg, rename, errno);
        return UV__ERROR;
    }
    rv = uvSyncDir(dir, errmsg);
    if (rv != 0) {
        return rv;
    }
    return 0;
}

int uvReadFully(const uvFd fd, void *buf, const size_t n, char *errmsg)
{
    int rv;
    rv = read(fd, buf, n);
    if (rv == -1) {
        uvErrMsgSys(errmsg, read, errno);
        return UV__ERROR;
    }
    assert(rv >= 0);
    if ((size_t)rv < n) {
        uvErrMsgPrintf(errmsg, "short read: %d bytes instead of %ld", rv, n);
        return UV__NODATA;
    }
    return 0;
}

int uvWriteFully(const uvFd fd, void *buf, const size_t n, char *errmsg)
{
    int rv;
    rv = write(fd, buf, n);
    if (rv == -1) {
        uvErrMsgSys(errmsg, write, errno);
        return UV__ERROR;
    }
    assert(rv >= 0);
    if ((size_t)rv < n) {
        uvErrMsgPrintf(errmsg, "short write: %d bytes instead of %ld", rv, n);
        return UV__ERROR;
    }
    return 0;
}

off_t uvLseek(uvFd fd, off_t offset, int whence)
{
	return lseek(fd, offset, whence);
}

ssize_t uvWritev(uvFd fd, const struct iovec *iov, int iovcnt)
{
	return writev(fd, iov, iovcnt);
}
#endif // UV_CCOWFSIO_ENABLED

int uvMakeFile(const uvDir dir,
               const uvFilename filename,
               struct raft_buffer *bufs,
               unsigned n_bufs,
               char *errmsg)
{
    int flags = O_WRONLY | O_CREAT | O_EXCL;
    uvFd fd;
    int rv;
    size_t size;
    unsigned i;
    size = 0;
    for (i = 0; i < n_bufs; i++) {
        size += bufs[i].len;
    }
    rv = uvOpenFile(dir, filename, flags, &fd, errmsg);
    if (rv != 0) {
        return rv;
    }
    rv = uvWritev(fd, (const struct iovec *)bufs, n_bufs);
    if (rv != (int)(size)) {
        if (rv == -1) {
            uvErrMsgSys(errmsg, writev, errno);
        } else {
            assert(rv >= 0);
            uvErrMsgPrintf(errmsg, "short write: %d only bytes written", rv);
        }
        goto err_after_file_open;
    }
    rv = uvFsync(fd);
    if (rv == -1) {
        uvErrMsgSys(errmsg, fsync, errno);
        goto err_after_file_open;
    }
    rv = uvCloseFile(fd);
    if (rv == -1) {
        uvErrMsgSys(errmsg, close, errno);
        goto err;
    }
    return 0;

err_after_file_open:
    uvCloseFile(fd);
err:
    return UV__ERROR;
}

int uvTruncateFile(const uvDir dir,
                   const uvFilename filename,
                   size_t offset,
                   char *errmsg)
{
    uvPath path;
    uvFd fd;
    int rv;
    uvJoin(dir, filename, path);
    rv = uvOpenFile(dir, filename, O_RDWR, &fd, errmsg);
    if (rv != 0) {
        goto err;
    }
    rv = uvFtruncate(fd, offset);
    if (rv == -1) {
        uvErrMsgSys(errmsg, ftruncate, errno);
        goto err_after_open;
    }
    rv = uvFsync(fd);
    if (rv == -1) {
        uvErrMsgSys(errmsg, fsync, errno);
        goto err_after_open;
    }
    uvCloseFile(fd);
    return 0;

err_after_open:
    uvCloseFile(fd);
err:
    return UV__ERROR;
}

int uvIsEmptyFile(const uvDir dir,
                  const uvFilename filename,
                  bool *empty,
                  char *errmsg)
{
    struct stat sb;
    int rv;
    rv = uvStatFile(dir, filename, &sb, errmsg);
    if (rv != 0) {
        return rv;
    }
    *empty = sb.st_size == 0 ? true : false;
    return 0;
}

int uvIsFilledWithTrailingZeros(const uvFd fd, bool *flag, char *errmsg)
{
    off_t size;
    off_t offset;
    char *data;
    size_t i;
    int rv;

    /* Save the current offset. */
    offset = uvLseek(fd, 0, SEEK_CUR);

    /* Figure the size of the rest of the file. */
    size = uvLseek(fd, 0, SEEK_END);
    if (size == -1) {
        uvErrMsgSys(errmsg, lseek, errno);
        return UV__ERROR;
    }
    size -= offset;

    /* Reposition the file descriptor offset to the original offset. */
    offset = uvLseek(fd, offset, SEEK_SET);
    if (offset == -1) {
        uvErrMsgSys(errmsg, lseek, errno);
        return UV__ERROR;
    }

    data = raft_malloc(size);
    if (data == NULL) {
        uvErrMsgPrintf(errmsg, "can't allocate read buffer");
        return UV__ERROR;
    }

    rv = uvReadFully(fd, data, size, errmsg);
    if (rv != 0) {
        return rv;
    }

    for (i = 0; i < (size_t)size; i++) {
        if (data[i] != 0) {
            *flag = false;
            goto done;
        }
    }

    *flag = true;

done:
    raft_free(data);

    return 0;
}

bool uvIsAtEof(const uvFd fd)
{
    off_t offset;
    off_t size;
    offset = uvLseek(fd, 0, SEEK_CUR); /* Get the current offset */
    size = uvLseek(fd, 0, SEEK_END);   /* Get file size */
    uvLseek(fd, offset, SEEK_SET);     /* Restore current offset */
    return offset == size;           /* Compare current offset and size */
}

void uvTryUnlinkFile(const char *dir, const char *filename)
{
    uvErrMsg errmsg;
    uvUnlinkFile(dir, filename, errmsg);
}

/* Check if direct I/O is possible on the given fd. */
static int probeDirectIO(int fd, size_t *size, char *errmsg)
{
    int flags;             /* Current fcntl flags. */
    struct statfs fs_info; /* To check the file system type. */
    void *buf;             /* Buffer to use for the probe write. */
    int rv;

    flags = fcntl(fd, F_GETFL);
    rv = fcntl(fd, F_SETFL, flags | O_DIRECT);

    if (rv == -1) {
        if (errno != EINVAL) {
            /* UNTESTED: the parameters are ok, so this should never happen. */
            uvErrMsgSys(errmsg, fnctl, errno);
            return UV__ERROR;
        }
        rv = fstatfs(fd, &fs_info);
        if (rv == -1) {
            /* UNTESTED: in practice ENOMEM should be the only failure mode */
            uvErrMsgSys(errmsg, fstatfs, errno);
            return UV__ERROR;
        }
        switch (fs_info.f_type) {
            case 0x01021994: /* TMPFS_MAGIC */
            case 0x2fc12fc1: /* ZFS magic */
                *size = 0;
                return 0;
            default:
                /* UNTESTED: this is an unsupported file system. */
                uvErrMsgPrintf(errmsg, "unsupported file system: %lx",
                               fs_info.f_type);
                return UV__ERROR;
        }
    }

    /* Try to peform direct I/O, using various buffer size. */
    *size = 4096;
    while (*size >= 512) {
        buf = raft_aligned_alloc(*size, *size);
        if (buf == NULL) {
            /* UNTESTED: TODO */
            uvErrMsgPrintf(errmsg, "can't allocate write buffer");
            return UV__ERROR;
        }
        memset(buf, 0, *size);
        rv = write(fd, buf, *size);
        raft_free(buf);
        if (rv > 0) {
            /* Since we fallocate'ed the file, we should never fail because of
             * lack of disk space, and all bytes should have been written. */
            assert(rv == (int)(*size));
            return 0;
        }
        assert(rv == -1);
        if (errno != EIO && errno != EOPNOTSUPP) {
            /* UNTESTED: this should basically fail only because of disk errors,
             * since we allocated the file with posix_fallocate. */

            /* FIXME: this is a workaround because shiftfs doesn't return EINVAL
             * in the fnctl call above, for example when the underlying fs is
             * ZFS. */
            if (errno == EINVAL && *size == 4096) {
                *size = 0;
                return 0;
            }

            uvErrMsgSys(errmsg, write, errno);
            return UV__ERROR;
        }
        *size = *size / 2;
    }

    *size = 0;
    return 0;
}

#if defined(RWF_NOWAIT)
/* Check if fully non-blocking async I/O is possible on the given fd. */
static int probeAsyncIO(int fd, size_t size, bool *ok, char *errmsg)
{
    void *buf;                  /* Buffer to use for the probe write */
    aio_context_t ctx = 0;      /* KAIO context handle */
    struct iocb iocb;           /* KAIO request object */
    struct iocb *iocbs = &iocb; /* Because the io_submit() API sucks */
    struct io_event event;      /* KAIO response object */
    int n_events;
    int rv;

    /* Setup the KAIO context handle */
    rv = uvIoSetup(1, &ctx, errmsg);
    if (rv != 0) {
        /* UNTESTED: in practice this should fail only with ENOMEM */
        return rv;
    }

    /* Allocate the write buffer */
    buf = raft_aligned_alloc(size, size);
    if (buf == NULL) {
        /* UNTESTED: define a configurable allocator that can fail? */
        uvErrMsgPrintf(errmsg, "can't allocate write buffer");
        return UV__ERROR;
    }
    memset(buf, 0, size);

    /* Prepare the KAIO request object */
    memset(&iocb, 0, sizeof iocb);
    iocb.aio_lio_opcode = IOCB_CMD_PWRITE;
    *((void **)(&iocb.aio_buf)) = buf;
    iocb.aio_nbytes = size;
    iocb.aio_offset = 0;
    iocb.aio_fildes = fd;
    iocb.aio_reqprio = 0;
    iocb.aio_rw_flags |= RWF_NOWAIT | RWF_DSYNC;

    /* Submit the KAIO request */
    rv = uvIoSubmit(ctx, 1, &iocbs, errmsg);
    if (rv != 0) {
        /* UNTESTED: in practice this should fail only with ENOMEM */
        raft_free(buf);
        uvTryIoDestroy(ctx);
        /* On ZFS 0.8 this is not properly supported yet. */
        if (errno == EOPNOTSUPP) {
            *ok = false;
            return 0;
        }
        return rv;
    }

    /* Fetch the response: will block until done. */
    rv = uvIoGetevents(ctx, 1, 1, &event, NULL, &n_events, errmsg);
    assert(rv == 0);
    assert(n_events == 1);

    /* Release the write buffer. */
    raft_free(buf);

    /* Release the KAIO context handle. */
    rv = uvIoDestroy(ctx, errmsg);
    if (rv != 0) {
        return rv;
    }

    if (event.res > 0) {
        assert(event.res == (int)size);
        *ok = true;
    } else {
        /* UNTESTED: this should basically fail only because of disk errors,
         * since we allocated the file with posix_fallocate and the block size
         * is supposed to be correct. */
        assert(event.res != EAGAIN);
        *ok = false;
    }

    return 0;
}

#endif /* RWF_NOWAIT */

#if defined(UV_CCOWFSIO_ENABLED)
int uvProbeIoCapabilities(const uvDir dir,
                          size_t *direct,
                          bool *async,
                          char *errmsg)
{
	char *root = NULL, *fstr, *p;
	uvFilename filename; /* Filename of the probe file */
	uvPath path;         /* Full path of the probe file */
	inode_t di, ino;
	int err;

	*async = false;
	*direct = false;

	ci_t *ci = findFSExportByDir((char*)dir, &di);
	if (!ci || di == 0) {
		uvErrMsgSys(errmsg, mkstemp, EACCES);
		return UV__ERROR;
	}

	/* Get tenant */
	p = strchr(dir, '/');
	/* Get bucket */
	if (p)
		p = strchr(p+1,'/');
	/* Get root */
	if (p)
		root = strchr(p+1,'/');

	/* Create a temporary probe file. */
	tmpnam(filename);
	fstr = strrchr(filename, '/');
	fstr++;

	assert(root[0] == '/');
	err = ccow_fsio_find(ci, root, &di);
	assert(err == 0);

	err = uvCheckAccess(ci, di);
	if (err) {
		uvErrMsgSys(errmsg, mkstemp, EACCES);
		return UV__ERROR;
	}

        err = ccow_fsio_touch(ci, di, fstr, 0600, geteuid(), getegid(), &ino);
	if (err) {
		uvErrMsgSys(errmsg, mkstemp, EACCES);
		return UV__ERROR;
	}
	err = ccow_fsio_delete(ci, di, (char*)filename);
	assert(err == 0);
	return 0;
}
#else
int uvProbeIoCapabilities(const uvDir dir,
                          size_t *direct,
                          bool *async,
                          char *errmsg)
{
    uvFilename filename; /* Filename of the probe file */
    uvPath path;         /* Full path of the probe file */
    int fd;              /* File descriptor of the probe file */
    int rv;

    if (dir[0] != '/') {
        *async = false;
        *direct = false;
        return 0;
    }

    /* Create a temporary probe file. */
    strcpy(filename, ".probe-XXXXXX");
    uvJoin(dir, filename, path);
    fd = mkstemp(path);
    if (fd == -1) {
        uvErrMsgSys(errmsg, mkstemp, errno);
        goto err;
    }
    rv = posix_fallocate(fd, 0, 4096);
    if (rv != 0) {
        uvErrMsgSys(errmsg, posix_fallocate, rv);
        goto err_after_file_open;
    }
    unlink(path);

    /* Check if we can use direct I/O. */
    rv = probeDirectIO(fd, direct, errmsg);
    if (rv != 0) {
        goto err_after_file_open;
    }

#if !defined(RWF_NOWAIT)
    /* We can't have fully async I/O, since io_submit might potentially block.
     */
    *async = false;
#else
    /* If direct I/O is not possible, we can't perform fully asynchronous
     * I/O, because io_submit might potentially block. */
    if (*direct == 0) {
        *async = false;
        goto out;
    }
    rv = probeAsyncIO(fd, *direct, async, errmsg);
    if (rv != 0) {
        goto err_after_file_open;
    }
#endif /* RWF_NOWAIT */

#if defined(RWF_NOWAIT)
out:
#endif /* RWF_NOWAIT */
    close(fd);
    return 0;

err_after_file_open:
    close(fd);
err:
    return UV__ERROR;
}
#endif

int uvSetDirectIo(int fd, char *errmsg)
{
    int flags; /* Current fcntl flags */
    int rv;
    flags = fcntl(fd, F_GETFL);
    rv = fcntl(fd, F_SETFL, flags | O_DIRECT);
    if (rv == -1) {
        uvErrMsgSys(errmsg, fnctl, errno);
        return UV__ERROR;
    }
    return 0;
}

int uvIoSetup(unsigned nr, aio_context_t *ctxp, char *errmsg)
{
    int rv;
    rv = syscall(__NR_io_setup, nr, ctxp);
    if (rv == -1) {
        uvErrMsgSys(errmsg, io_setup, errno);
        return UV__ERROR;
    }
    return 0;
}

int uvIoDestroy(aio_context_t ctx, char *errmsg)
{
    int rv;
    rv = syscall(__NR_io_destroy, ctx);
    if (rv == -1) {
        uvErrMsgSys(errmsg, io_destroy, errno);
        return UV__ERROR;
    }
    return 0;
}

void uvTryIoDestroy(aio_context_t ctx)
{
    uvErrMsg errmsg;
    uvIoDestroy(ctx, errmsg);
}

int uvIoSubmit(aio_context_t ctx, long nr, struct iocb **iocbpp, char *errmsg)
{
    int rv;
    rv = syscall(__NR_io_submit, ctx, nr, iocbpp);
    if (rv == -1) {
        uvErrMsgSys(errmsg, io_submit, errno);
        switch (errno) {
            case EOPNOTSUPP:
                return UV__NOTSUPP;
            case EAGAIN:
                return UV__AGAIN;
            default:
                return UV__ERROR;
        }
    }
    assert(rv == nr); /* TODO: can something else be returned? */
    return 0;
}

int uvIoGetevents(aio_context_t ctx,
                  long min_nr,
                  long max_nr,
                  struct io_event *events,
                  struct timespec *timeout,
                  int *nr,
                  char *errmsg)
{
    int rv;
    do {
        rv = syscall(__NR_io_getevents, ctx, min_nr, max_nr, events, timeout);
    } while (rv == -1 && errno == EINTR);

    if (rv == -1) {
        uvErrMsgSys(errmsg, io_getevents, errno);
        return UV__ERROR;
    }
    assert(rv >= min_nr);
    assert(rv <= max_nr);
    *nr = rv;
    return 0;
}
