#include "uv_os.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <uv.h>

#include "assert.h"
#include "err.h"
#include "syscall.h"

/* Default permissions when creating a directory. */
#define DEFAULT_DIR_PERM 0700

void UvOsJoin(const char *dir, const char *filename, char *path)
{
    assert(UV__DIR_HAS_VALID_LEN(dir));
    assert(UV__FILENAME_HAS_VALID_LEN(filename));
    strcpy(path, dir);
    strcat(path, "/");
    strcat(path, filename);
}

#if UV_CCOWFSIO_ENABLED
static void skip_free(void *ptr) {}
static int ccowfsio_init = 0;

struct ccow_dir_data {
    ci_t *ci;
    struct dirent **dir_ents;
    uint64_t dir_count;
    uv_cond_t wait_cond;
    uv_mutex_t wait_mutex;
};

static int
list_cb(inode_t parent, fsio_dir_entry *dir_entry, uint64_t count, void *ptr)
{
    int rv = 0;
    uint64_t i;
    struct ccow_dir_data *dirp = ptr;
    assert (dirp != NULL);

    if (dirp->dir_ents) {
        dirp->dir_ents = realloc(dirp->dir_ents,
            (count + dirp->dir_count) * sizeof (struct dirent *));
    } else {
        dirp->dir_ents = calloc(count + dirp->dir_count,
                sizeof (struct dirent *));
    }
    if (dirp->dir_ents == NULL) {
        rv = 1;
        goto _out;
    }

    uint64_t idx = dirp->dir_count;
    for (i = 0; i < count; i++) {
        unsigned short len;
        dirp->dir_ents[idx] = calloc(1, sizeof (struct dirent));
        if (dirp->dir_ents[idx] == NULL) {
            rv = 1;
            break;
        }

        dirp->dir_ents[idx]->d_ino = dir_entry[i].inode;
        len = strlen(dir_entry[i].name) > 255 ?
              255 : (unsigned short)strlen(dir_entry[i].name);
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
    return rv;
}

static int
uvCheckAccess(ci_t *ci, inode_t inode)
{
    struct stat sb;
    uid_t euid;
    gid_t egid;
    int err;

    euid = geteuid();
    egid = getegid();

    /* root does not require permission */
    if (euid == 0) {
        return 0;
    }

    memset(&sb, 0, sizeof sb);
    err = ccow_fsio_get_file_stat(ci, inode, &sb);
    if (err)
        return err;

    if (euid == sb.st_uid) {
        if (!(sb.st_mode & S_IXUSR) || !(sb.st_mode & S_IRUSR))
            return -EACCES;
        if (!(sb.st_mode & S_IWUSR))
            return -EPERM;
        return 0;
    }

    if (egid == sb.st_gid) {
        if (!(sb.st_mode & S_IXGRP) || !(sb.st_mode & S_IRGRP))
            return -EACCES;
        if (!(sb.st_mode & S_IWGRP))
            return -EPERM;
        return 0;
    }
    if (!(sb.st_mode & S_IXOTH) || !(sb.st_mode & S_IROTH))
        return -EACCES;
    if (!(sb.st_mode & S_IWOTH))
        return -EPERM;
    return 0;
}

extern int
ccow_fsio_find_export(char *cid, size_t cid_size, char *tid, size_t tid_size,
    char *bid, size_t bid_size, ci_t ** out_ci);

int
findFSExportByDir(char *dir, inode_t *subdir_inode,
        ci_t **ci, bool create_export_dir)
{
    char cid[2048], tid[2048], bid[2048], subdir[2048];
    size_t cid_size, tid_size, bid_size;
    int err = 0;

    *cid = *tid = *bid = *subdir = 0;
    *subdir_inode = 0;

    if (dir == NULL || dir[0] == '\0')
        return ENOENT;

    if (sscanf(dir, "%2047[^/]/%2047[^/]/%2047[^/]/%2047[^\n]",
            cid, tid, bid, subdir) < 3) {
        return ENOENT;
    }
    cid_size = strlen(cid) + 1;
    tid_size = strlen(tid) + 1;
    bid_size = strlen(bid) + 1;

    /* Initialse only after resonable path is determined */
    if (!ccowfsio_init) {
        err = ccow_fsio_init();
        if (err)
            return err;
        ccowfsio_init = 1;
    }

    ccow_fsio_find_export(cid, cid_size, tid, tid_size, bid, bid_size, ci);
    if (!*ci) {
        *ci = ccow_fsio_ci_alloc();
        if (!*ci) {
            return ENOMEM;
        }

        char ccowpath[UV__PATH_SZ];
        snprintf(ccowpath, sizeof(ccowpath), "%s/etc/ccow/ccow.json",
            nedge_path());

        char exppath[UV__PATH_SZ];
        snprintf(exppath, sizeof(exppath), "%s/%s/%s", cid, tid, bid);

        err = ccow_fsio_create_export(*ci, exppath, ccowpath,
            4096, NULL, NULL);
        if (err) {
            ccow_fsio_ci_free(*ci);
            return err;
        }

        if (create_export_dir && *subdir) {
            err = ccow_fsio_mkdir(*ci, CCOW_FSIO_ROOT_INODE, subdir,
                S_IFDIR | 0750, 0, 0, subdir_inode);
            if (err && err != EEXIST) {
                ccow_fsio_delete_export(*ci);
                ccow_fsio_ci_free(*ci);
                return err;
            }
        }
    }

    if (*subdir) {
        memmove(subdir+1, subdir, strlen(subdir)+1); *subdir = '/';
        err = ccow_fsio_find(*ci, subdir, subdir_inode);
        if (err) {
            return err;
        } else {
            if (!INODE_IS_DIR(*subdir_inode)) {
                char *p = strrchr(subdir, '/');
                *p = '\0';
                if (*subdir) {
                    err = ccow_fsio_find(*ci, subdir, subdir_inode);
                    if (err)
                        return err;
                }
            }
        }
    } else
        *subdir_inode = CCOW_FSIO_ROOT_INODE;

    return uvCheckAccess(*ci, *subdir_inode);
}

int
UvOsMaybeEdgefsPath(const char *path, bool *maybeEdgeFsPath)
{
    int rv, count = 0;
    struct stat sb;
    char *p = path;

    *maybeEdgeFsPath = false;

    /* Make sure that dir with ccow hierarchy does not exist */
    rv = stat(path, &sb);
    if (rv == 0 && (sb.st_mode & S_IFMT) != S_IFDIR) {
        return UV_ENOTDIR;
    }

    /* If dir with ccow hierarchy exists, deny further op */
    if (rv == 0 || errno == EACCES) {
        return UV_EACCES;
    }

    if (rv !=0 && errno == ENOENT) {
        /*
         * Check if there are at least two components in the path
         * cluster/tenant/bucket
         */
        p = strchr(path, '/');
        while (p != NULL) {
            count++;
            p = strchr(p + 1, '/');
        }
        *maybeEdgeFsPath = count > 1 ? true : false;
        rv = count > 1 ? 0 : UV_ENOENT;
    } else {
        rv = uv_translate_sys_error(errno);
    }
    return rv;
}

int UvOsOpen(const char *path, int flags, int mode, uvFd *fd)
{
    int rv;
    bool edgefsPath = false;
    ci_t *ci;
    char *p, *filename;
    char dir[UV__PATH_SZ];
    inode_t subdir_inode, file_inode;

    rv = UvOsMaybeEdgefsPath(path, &edgefsPath);
    if (!edgefsPath)
        return rv;

    uvFd f = calloc(1, sizeof(*f));

    if (!f) {
        return uv_translate_sys_error(ENOMEM);
    }

    assert(UV__PATH_SZ > strlen(path));
    strncpy(dir, path, UV__PATH_SZ - 1);

    /* Extract filename and subdir */
    p = strrchr(dir, '/');
    if (p) {
        filename = p + 1;
        *p = '\0';
    }

    rv = findFSExportByDir(dir, &subdir_inode, &ci, false);

    if (rv) {
        free(f);
        return uv_translate_sys_error(abs(rv));
    }

    if (flags & O_CREAT) {
        rv = ccow_fsio_touch(ci, subdir_inode, filename,
            0600, 0, 0, &file_inode);
        //if (rv && rv != EEXIST) {
        if (rv) {
            free(f);
            return uv_translate_sys_error(abs(rv));
        }
    } else {
        filename = NULL;

        /* Get tenant */
        p = strchr(path, '/');
        if (p) {
            /* Get bucket */
            p = strchr(p + 1, '/');
            if (p) {
                filename = strchr(p + 1, '/');
            }
        }
        rv = ccow_fsio_find(ci, filename, &file_inode);
        if (rv) {
            free(f);
            return uv_translate_sys_error(abs(rv));
        }
    }

    rv = ccow_fsio_openi(ci, file_inode, &f->file, flags);
    if (rv) {
        free(f);
        return uv_translate_sys_error(abs(rv));
    }

    ccow_fsio_write_free_set(f->file, skip_free);

    *fd = f;
    return 0;
}

int UvOsClose(uvFd fd)
{
    int rv = 0;

    if (fd->file) {
        rv = ccow_fsio_close(fd->file);
        fd->file = NULL;
    }
    free(fd);
    return uv_translate_sys_error(abs(rv));
}

int UvOsFallocate(uvFd fd, off_t offset, off_t len)
{
    int rv;
    off_t remaining, new_off, write_len;
    char *buf;
    size_t result;
    struct stat sb;

    rv = ccow_fsio_get_file_stat(fd->file->ci, fd->file->ino, &sb);
    if (rv == 0) {
        /* Do nothing if offset + len < sb.st_size */
        if (sb.st_size < offset + len) {

            /* Caculate the amount of buffer to be written */
            remaining = (offset + len) - sb.st_size;
            /*
             * Calculate the blocks to be written and write a block
             * at a time to avoid memory allocation failure. For aligned
             * writes better code could be written.
             */
    
            new_off = sb.st_size;
            while (remaining > 0) {
                if (remaining > sb.st_blksize) {
                    buf = calloc(1, (size_t)sb.st_blksize);
                    remaining -= sb.st_blksize;
                    write_len = sb.st_blksize;
                } else {
                    buf = calloc(1, (size_t)remaining);
                    write_len = remaining;
                    remaining = 0;
                }
                if (buf == NULL) {
                    rv = -ENOMEM;
                    break;
                }
                ccow_fsio_write_free_set(fd->file, free);
                rv = ccow_fsio_write(fd->file, (size_t)new_off,
                                     (size_t)write_len, buf, &result);
                if (rv != 0) {
                    rv = -EIO;
                    break;
                }
                new_off += write_len;
            }/* while - file allocate */

        }/* extending the file */
    }
 
    return uv_translate_sys_error(abs(rv));
}

int UvOsTruncate(uvFd fd, off_t offset)
{
    int rv;
    struct stat sb;

    /* TODO: Need a functions cow_fsio_truncate() */
    /* This is a workaround for truncate problem.
     * This will not release disk blocks.
     */
    rv = ccow_fsio_get_file_stat(fd->file->ci, fd->file->ino, &sb);
    if (rv == 0) {
        ccow_fsio_flush(fd->file);
        sb.st_size = offset;
        rv = ccow_fsio_set_file_stat(fd->file->ci, fd->file->ino, &sb);
    }
    return rv;
}

int UvOsFsync(uvFd fd)
{
    int rv;

    /*
     * TODO: Check if this also flushes metadata
     * May need another function which flushes both data and metadata
     */
    rv = ccow_fsio_flush(fd->file);
    return uv_translate_sys_error(abs(rv));
}

int UvOsFdatasync(uvFd fd)
{
    int rv;

    rv = ccow_fsio_flush(fd->file);
    return uv_translate_sys_error(abs(rv));
}

//int UvOsStat(const char *path, uv_stat_t *sb)
int UvOsStat(const char *path, uv_statbuf_t *sb)
{
    int rv = 0;
    inode_t dir_inode, file_inode;
    ci_t *ci;
    char cid[2048], tid[2048], bid[2048], subdir[2048];
    char *p, *filename;

    *cid = *tid = *bid = *subdir = 0;
    if (sscanf(path, "%2047[^/]/%2047[^/]/%2047[^/]/%2047[^\n]",
            cid, tid, bid, subdir) < 3) {
        return uv_translate_sys_error(ENOENT);
    }

    rv = findFSExportByDir(path, &dir_inode, &ci, false);

    /* Extract filename and subdir */
    if (*subdir) {
        p = strrchr(subdir, '/');
        if (p) {
            filename = p + 1;
            *p = '\0';
        } else {
            filename = &subdir[0];
        }
        rv = rv ? rv : ccow_fsio_lookup(ci, dir_inode, filename, &file_inode);
    } else {
        file_inode = dir_inode;
    }

    memset(sb, 0, sizeof *sb);
    rv = rv ? rv : ccow_fsio_get_file_stat(ci, file_inode, sb);
    return uv_translate_sys_error(abs(rv));

}

int UvOsWrite(uvFd fd,
              const uv_buf_t bufs[],
              unsigned int nbufs,
              int64_t offset)
{
    int rv;
    size_t nb_written, io_amount = 0;

    for (unsigned int i = 0; i < nbufs; i++) {
        rv = ccow_fsio_write(fd->file, (size_t)fd->offset,
            bufs[i].len, bufs[i].base, &nb_written);
        if (rv) {
            return uv_translate_sys_error(abs(rv));
        }

        if (nb_written == 0) {
            break;
        }

        io_amount += nb_written;
        fd->offset += (off_t)nb_written;
    }
    return (int)io_amount;
}

int UvOsUnlink(const char *path)
{
    int rv;
    inode_t subdir_inode;
    ci_t *ci;
    char *p, *filename;
    char dir[UV__PATH_SZ];

    strncpy(dir, path, UV__PATH_SZ - 1);

    /* Extract filename and subdir */
    p = strrchr(dir, '/');
    if (p) {
        filename = p + 1;
        *p = '\0';
    }

    rv = findFSExportByDir(dir, &subdir_inode, &ci, false);
    if (rv) {
        return uv_translate_sys_error(abs(rv));
    }

    rv = ccow_fsio_delete(ci, subdir_inode, filename);
    return uv_translate_sys_error(abs(rv));
}

int UvOsRename(const char *path1, const char *path2)
{
    int rv;
    ci_t *ci;
    inode_t dir_inode;
    char *p, *filename1, *filename2;
    char dir[UV__PATH_SZ];

    /* Note: Both path1 and path2 have same directories */
    strncpy(dir, path1, UV__PATH_SZ - 1);

    /* Extract filename and subdir */
    p = strrchr(dir, '/');
    if (p) {
        filename1 = p + 1;
        *p = '\0';
    }

    strncpy(dir, path2, UV__PATH_SZ - 1);

    /* Extract filename and subdir */
    p = strrchr(dir, '/');
    if (p) {
        filename2 = p + 1;
        *p = '\0';
    }

    rv = findFSExportByDir(dir, &dir_inode, &ci, false);
    rv = rv ? rv : ccow_fsio_move(ci, dir_inode, filename1,
                                  dir_inode, filename2);
    return uv_translate_sys_error(abs(rv));
}

int UvOsSetDirectIo(uvFd fd)
{
    /* FIXME: How to support direct IO */
    return 0;
}

int UvOsScanDir(const char *dir,
              struct dirent ***entries,
              uint64_t *n_entries,
              char *errmsg)
{
    inode_t di;
    ci_t *ci;
    int rv = 0;
    bool eof = false;
    struct ccow_dir_data dir_info;
    char *start = NULL;

    rv = findFSExportByDir((char *)dir, &di, &ci, false);
    if (rv) {
        return uv_translate_sys_error(abs(rv));
    }
    memset(&dir_info, 0, sizeof dir_info);
    uv_cond_init(&dir_info.wait_cond);
    uv_mutex_init(&dir_info.wait_mutex);

    while (rv == 0 && !eof) {
        start = dir_info.dir_count ?
            dir_info.dir_ents[dir_info.dir_count - 1]->d_name : NULL;
        rv = ccow_fsio_readdir_cb4(ci, di, list_cb, start, &dir_info, &eof);
        if (rv == 0 && !eof) {
            uv_mutex_lock(&dir_info.wait_mutex);
            uv_cond_wait(&dir_info.wait_cond, &dir_info.wait_mutex);
            uv_mutex_unlock(&dir_info.wait_mutex);
        }
    }
    uv_cond_destroy(&dir_info.wait_cond);
    uv_mutex_destroy(&dir_info.wait_mutex);
    *entries = dir_info.dir_ents;
    *n_entries = dir_info.dir_count;
    return uv_translate_sys_error(abs(rv));
}

off_t UvOsLseek(uvFd fd, off_t offset, int whence)
{
    int rv;

    if (whence == SEEK_SET) {
        fd->offset = offset;
    return offset;
    } else if (whence == SEEK_CUR) {
    fd->offset += offset;
    return fd->offset;
    } else if (whence == SEEK_END) {
    struct stat stat;
    rv = ccow_fsio_get_file_stat(fd->file->ci, fd->file->ino, &stat);
    if (rv)
        return (off_t)-1;
    fd->offset = stat.st_size + offset;
    }
    return fd->offset;
}

#else

int UvOsOpen(const char *path, int flags, int mode, uvFd *fd)
{
    struct uv_fs_s req;
    int rv;
    rv = uv_fs_open(NULL, &req, path, flags, mode, NULL);
    if (rv < 0) {
        return rv;
    }
    *fd = rv;
    return 0;
}

int UvOsClose(uvFd fd)
{
    struct uv_fs_s req;
    return uv_fs_close(NULL, &req, fd, NULL);
}

int UvOsFallocate(uvFd fd, off_t offset, off_t len)
{
    int rv;
    rv = posix_fallocate(fd, offset, len);
    if (rv != 0) {
        /* From the manual page:
         *
         *   posix_fallocate() returns zero on success, or an error number on
         *   failure.  Note that errno is not set.
         */
        return -rv;
    }
    return 0;
}

int UvOsTruncate(uvFd fd, off_t offset)
{
    struct uv_fs_s req;
    return uv_fs_ftruncate(NULL, &req, fd, offset, NULL);
}

int UvOsFsync(uvFd fd)
{
    struct uv_fs_s req;
    return uv_fs_fsync(NULL, &req, fd, NULL);
}

int UvOsFdatasync(uvFd fd) {
    struct uv_fs_s req;
    return uv_fs_fdatasync(NULL, &req, fd, NULL);
}

//int UvOsStat(const char *path, uv_stat_t *sb)
int UvOsStat(const char *path, uv_statbuf_t *sb)
{
    struct uv_fs_s req;
    int rv;
    rv = uv_fs_stat(NULL, &req, path, NULL);
    if (rv != 0) {
        return rv;
    }
    memcpy(sb, &req.statbuf, sizeof *sb);
    return 0;
}

int UvOsWrite(uvFd fd,
              const uv_buf_t bufs[],
              unsigned int nbufs,
              int64_t offset)
{
    struct uv_fs_s req;
    return uv_fs_write(NULL, &req, fd, bufs, nbufs, offset, NULL);
}

int UvOsUnlink(const char *path)
{
    struct uv_fs_s req;
    return uv_fs_unlink(NULL, &req, path, NULL);
}

int UvOsRename(const char *path1, const char *path2)
{
    struct uv_fs_s req;
    return uv_fs_rename(NULL, &req, path1, path2, NULL);
}

int UvOsSetDirectIo(uvFd fd)
{
    int flags; /* Current fcntl flags */
    int rv;
    flags = fcntl(fd, F_GETFL);
    rv = fcntl(fd, F_SETFL, flags | UV_FS_O_DIRECT);
    if (rv == -1) {
        return -errno;
    }
    return 0;
}

off_t UvOsLseek(uvFd fd, off_t offset, int whence)
{
    return lseek(fd, offset, whence);
}

#endif /* UV_CCOWFSIO_ENABLED */

int UvOsIoSetup(unsigned nr, aio_context_t *ctxp)
{
    int rv;
    rv = io_setup(nr, ctxp);
    if (rv == -1) {
        return -errno;
    }
    return 0;
}

int UvOsIoDestroy(aio_context_t ctx)
{
    int rv;
    rv = io_destroy(ctx);
    if (rv == -1) {
        return -errno;
    }
    return 0;
}

int UvOsIoSubmit(aio_context_t ctx, long nr, struct iocb **iocbpp)
{
    int rv;
    rv = io_submit(ctx, nr, iocbpp);
    if (rv == -1) {
        return -errno;
    }
    assert(rv == nr); /* TODO: can something else be returned? */
    return 0;
}

int UvOsIoGetevents(aio_context_t ctx,
                    long min_nr,
                    long max_nr,
                    struct io_event *events,
                    struct timespec *timeout)
{
    int rv;
    do {
        rv = io_getevents(ctx, min_nr, max_nr, events, timeout);
    } while (rv == -1 && errno == EINTR);

    if (rv == -1) {
        return -errno;
    }
    assert(rv >= min_nr);
    assert(rv <= max_nr);
    return rv;
}

int UvOsEventfd(unsigned int initval, int flags)
{
    int rv;
    /* At the moment only UV_FS_O_NONBLOCK is supported */
    assert(flags == UV_FS_O_NONBLOCK);
    flags = EFD_NONBLOCK|EFD_CLOEXEC;
    rv = eventfd(initval, flags);
    if (rv == -1) {
        return -errno;
    }
    return rv;
}
