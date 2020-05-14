/* Asynchronous API to write a file. */

#ifndef UV_EDGEFS_WRITER_H_
#define UV_EDGEFS_WRITER_H_

#include <stdbool.h>

#include "uv_os.h"

/* Handle to an open file. */
struct uvFile;

/* Perform asynchronous writes to a single file. */
struct UvWriter;

/* Callback called after the memory associated with a file handle can be
 * released. */
typedef void (*UvWriterCloseCb)(struct UvWriter *w);

struct UvWriter
{
    void *data;                    /* User data */
    struct uv_loop_s *loop;        /* Event loop */
    uvFd fd;                       /* File handle */
    bool async;                    /* Whether fully async I/O is supported */
    UvWriterCloseCb close_cb;      /* Close callback */
    bool closing;                  /* Whether we're closing or closed */
    char *errmsg;                  /* Description of last error */
};

/* Initialize a file writer. */
int UvWriterInit(struct UvWriter *w,
                 struct uv_loop_s *loop,
                 uvFd fd,
                 bool direct /* Whether to use direct I/O */,
                 bool async /* Whether async I/O is available */,
                 unsigned max_concurrent_writes,
                 char *errmsg);

/* Close the given file and release all associated resources. */
void UvWriterClose(struct UvWriter *w, UvWriterCloseCb cb);

/* Write request. */
struct UvWriterReq;

/* Callback called after a write request has been completed. */
typedef void (*UvWriterReqCb)(struct UvWriterReq *req, int status);

struct UvWriterReq
{
    void *data;              /* User data */
    struct UvWriter *writer; /* Originating writer */
    size_t len;              /* Total number of bytes to write */
    int status;              /* Request result code */
    struct uv_work_s work;   /* To execute logic in the threadpool */
    UvWriterReqCb cb;        /* Callback to invoke upon request completion */
    uv_buf_t *bufs;
    unsigned bufs_count;
    size_t offset;
    char errmsg[256];        /* Error description (for thread-safety) */
};

/* Asynchronously write data to the underlying file. */
int UvWriterSubmit(struct UvWriter *w,
                   struct UvWriterReq *req,
                   const uv_buf_t bufs[],
                   unsigned n,
                   size_t offset,
                   UvWriterReqCb cb);

#endif /* UV_EDGEFS_WRITER_H_ */
