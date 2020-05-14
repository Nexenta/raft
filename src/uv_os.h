/* Operating system related utilities. */

#ifndef UV_OS_H_
#define UV_OS_H_

#include <fcntl.h>
#include <linux/aio_abi.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <uv.h>

/* For backward compat with older libuv */
#if !defined(UV_FS_O_RDONLY)
#define UV_FS_O_RDONLY O_RDONLY
#endif

#if !defined(UV_FS_O_DIRECTORY)
#define UV_FS_O_DIRECTORY O_DIRECTORY
#endif

#if !defined(UV_FS_O_WRONLY)
#define UV_FS_O_WRONLY O_WRONLY
#endif

#if !defined(UV_FS_O_RDWR)
#define UV_FS_O_RDWR O_RDWR
#endif

#if !defined(UV_FS_O_CREAT)
#define UV_FS_O_CREAT O_CREAT
#endif

#if !defined(UV_FS_O_TRUNC)
#define UV_FS_O_TRUNC O_TRUNC
#endif

#if !defined(UV_FS_O_EXCL)
#define UV_FS_O_EXCL O_EXCL
#endif

#if !defined(UV_FS_O_DIRECT)
#define UV_FS_O_DIRECT O_DIRECT
#endif

#if !defined(UV_FS_O_NONBLOCK)
#define UV_FS_O_NONBLOCK O_NONBLOCK
#endif

/* Maximum size of a full file system path string. */
#define UV__PATH_SZ 1024

/* Maximum length of a filename string. */
#define UV__FILENAME_LEN 128

/* Length of path separator. */
#define UV__SEP_LEN 1 /* strlen("/") */

/* True if STR's length is at most LEN. */
#define LEN_AT_MOST_(STR, LEN) (strnlen(STR, LEN + 1) <= LEN)

/* Maximum length of a directory path string. */
#define UV__DIR_LEN (UV__PATH_SZ - UV__SEP_LEN - UV__FILENAME_LEN - 1)

/* True if the given DIR string has at most UV__DIR_LEN chars. */
#define UV__DIR_HAS_VALID_LEN(DIR) LEN_AT_MOST_(DIR, UV__DIR_LEN)

/* True if the given FILENAME string has at most UV__FILENAME_LEN chars. */
#define UV__FILENAME_HAS_VALID_LEN(FILENAME) \
    LEN_AT_MOST_(FILENAME, UV__FILENAME_LEN)

#if UV_CCOWFSIO_ENABLED
#include <stdlib.h>
#include <dirent.h>
#include "ccowfsio.h"

struct uvFile
{
    ccow_fsio_file_t *file;
    off_t offset;
};
typedef struct uvFile* uvFd;

int findFSExportByDir(char *dir, inode_t *subdir_inode,
		ci_t **ci, bool create_export_dir);
int UvOsScanDir(const char *dir, struct dirent ***entries,
              uint64_t *n_entries, char *errmsg);
int UvOsMaybeEdgefsPath(const char *path, bool *maybeEdgeFsPath);
#else
typedef uv_file uvFd;
#endif

/* Portable open() */
int UvOsOpen(const char *path, int flags, int mode, uvFd *fd);

/* Portable close() */
int UvOsClose(uvFd fd);

/* TODO: figure a portable abstraction. */
int UvOsFallocate(uvFd fd, off_t offset, off_t len);

/* Portable truncate() */
int UvOsTruncate(uvFd fd, off_t offset);

/* Portable fsync() */
int UvOsFsync(uvFd fd);

/* Portable fdatasync() */
int UvOsFdatasync(uvFd fd);

/* Portable stat() */
/* Changing uv_stat_t to uv_statbuf_t - for compatibility with old libuv */
int UvOsStat(const char *path, uv_statbuf_t *sb);

/* Portable write() */
int UvOsWrite(uvFd fd,
              const uv_buf_t bufs[],
              unsigned int nbufs,
              int64_t offset);

/* Portable unlink() */
int UvOsUnlink(const char *path);

/* Portable rename() */
int UvOsRename(const char *path1, const char *path2);

/* Join dir and filename into a full OS path. */
void UvOsJoin(const char *dir, const char *filename, char *path);

/* TODO: figure a portable abstraction. */
int UvOsIoSetup(unsigned nr, aio_context_t *ctxp);
int UvOsIoDestroy(aio_context_t ctx);
int UvOsIoSubmit(aio_context_t ctx, long nr, struct iocb **iocbpp);
int UvOsIoGetevents(aio_context_t ctx,
                    long min_nr,
                    long max_nr,
                    struct io_event *events,
                    struct timespec *timeout);
int UvOsEventfd(unsigned int initval, int flags);
int UvOsSetDirectIo(uvFd fd);
off_t UvOsLseek(uvFd fd, off_t offset, int whence);

UV_EXTERN uv_err_t uv__new_artificial_error(uv_err_code ec);
UV_EXTERN uv_err_code uv_translate_sys_error(int sys_errno);

/* Format an error message caused by a failed system call or stdlib function. */
#define UvOsErrMsg(ERRMSG, SYSCALL, ERRNUM)                    \
    {                                                          \
        uv_err_t err_ = uv__new_artificial_error(ERRNUM);      \
        ErrMsgPrintf(ERRMSG, "%s", uv_strerror(err_));         \
        ErrMsgWrapf(ERRMSG, SYSCALL);                          \
    }
#if 0
/* Format an error message caused by a failed system call or stdlib function. */
#define UvOsErrMsg(ERRMSG, SYSCALL, ERRNUM)              \
    {                                                    \
        ErrMsgPrintf(ERRMSG, "%s", uv_strerror(ERRNUM)); \
        ErrMsgWrapf(ERRMSG, SYSCALL);                    \
    }
#endif /* UV_CCOWFSIO_ENABLED */

#endif /* UV_OS_H_ */
