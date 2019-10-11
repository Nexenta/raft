#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/raft.h"
#include "../include/raft/uv.h"

#define N_SERVERS 3    /* Number of servers in the example cluster */
#define APPLY_RATE 125 /* Apply a new entry every 125 milliseconds */

/********************************************************************
 *
 * Sample application FSM that just increases a counter.
 *
 ********************************************************************/

/* Custom logging function which include the server ID. */
static void emit(struct raft_logger *l,
                 int level,
                 raft_time time,
                 const char *file,
                 int line,
                 const char *format,
                 ...)
{
    va_list args;
    unsigned id = *(unsigned *)l->impl;
    char buf[2048];
    (void)time;
    if (level < l->level) {
        return;
    }
    sprintf(buf, "%d: %30s:%*d - ", id, file, 3, line);
    va_start(args, format);
    vsprintf(buf + strlen(buf), format, args);
    va_end(args);
    fprintf(stderr, "%s\n", buf);
}

struct fsm
{
    int count;
};

static int fsmApply(struct raft_fsm *fsm,
                    const struct raft_buffer *buf,
                    void **result)
{
    struct fsm *f = fsm->data;
    if (buf->len != 8) {
        return RAFT_MALFORMED;
    }
    f->count += *(uint64_t *)buf->base;
    *result = &f->count;
    return 0;
}

static int fsmSnapshot(struct raft_fsm *fsm,
                       struct raft_buffer *bufs[],
                       unsigned *n_bufs)
{
    struct fsm *f = fsm->data;
    *n_bufs = 1;
    *bufs = raft_malloc(sizeof **bufs);
    if (*bufs == NULL) {
        return RAFT_NOMEM;
    }
    (*bufs)[0].len = sizeof(uint64_t);
    (*bufs)[0].base = raft_malloc((*bufs)[0].len);
    if ((*bufs)[0].base == NULL) {
        return RAFT_NOMEM;
    }
    *(uint64_t *)(*bufs)[0].base = f->count;
    return 0;
}

static int fsmRestore(struct raft_fsm *fsm, struct raft_buffer *buf)
{
    struct fsm *f = fsm->data;
    if (buf->len != sizeof(uint64_t)) {
        return RAFT_MALFORMED;
    }
    f->count = *(uint64_t *)buf->base;
    raft_free(buf->base);
    return 0;
}

static int fsmInit(struct raft_fsm *fsm)
{
    struct fsm *f = raft_malloc(sizeof *fsm);
    if (f == NULL) {
        return RAFT_NOMEM;
    }
    f->count = 0;
    fsm->version = 1;
    fsm->data = f;
    fsm->apply = fsmApply;
    fsm->snapshot = fsmSnapshot;
    fsm->restore = fsmRestore;
    return 0;
}

static void fsmClose(struct raft_fsm *f)
{
    raft_free(f->data);
}

/********************************************************************
 *
 * Example struct holding a single raft server instance and all its
 * dependencies.
 *
 ********************************************************************/

struct server
{
    struct uv_loop_s *loop;              /* UV loop. */
    struct uv_signal_s sigint;          /* To catch SIGINT and exit. */
    struct uv_timer_s timer;            /* To periodically apply a new entry. */
    const char *dir;                    /* Data dir of UV I/O backend. */
    struct raft_uv_transport transport; /* UV I/O backend transport. */
    struct raft_io io;                  /* UV I/O backend. */
    struct raft_fsm fsm;                /* Sample application FSM. */
    struct raft_logger logger;          /* Default logger. */
    unsigned id;                        /* Raft instance ID. */
    char address[64];                   /* Raft instance address. */
    struct raft raft;                   /* Raft instance. */
};

/* Convenience to emit a message. */
#define emitf(S, LEVEL, ...)                                                  \
    S->logger.emit(&S->logger, LEVEL, S->io.time(&S->io), __FILE__, __LINE__, \
                   ##__VA_ARGS__);

/* Final callback in the shutdown sequence, invoked after the timer handle has
 * been closed. */
static void timerCloseCb(struct uv_handle_s *handle)
{
    struct server *s = handle->data;
    raft_close(&s->raft, NULL);
}

/* Invoked after the signal handle has been closed. */
static void sigintCloseCb(struct uv_handle_s *handle)
{
    struct server *s = handle->data;
    uv_timer_stop(&s->timer);
    uv_close((uv_handle_t *)&s->timer, timerCloseCb);
}

/* Handler triggered by SIGINT. It will initiate the shutdown sequence. */
static void sigintCb(struct uv_signal_s *handle, int signum)
{
    struct server *s = handle->data;
    assert(signum == SIGINT);
    emitf(s, RAFT_INFO, "server: stopping");
    uv_signal_stop(handle);
    uv_close((uv_handle_t *)handle, sigintCloseCb);
}

/* Initialize the example server struct, without starting it yet. */
static int serverInit(struct server *s, const char *dir, unsigned id)
{
    struct raft_configuration configuration;
    struct timespec now;
    unsigned i;
    int rv;

    /* Ignore SIGPIPE, see https://github.com/joyent/libuv/issues/1254 */
    signal(SIGPIPE, SIG_IGN);

    /* Seed the random generator */
    timespec_get(&now, TIME_UTC);
    srandom(now.tv_nsec ^ now.tv_sec);

    /* Initialize the libuv loop. */
    s->loop = uv_loop_new();
    s->loop->data = s;

    /* Add a signal handler to stop the Raft engine upon SIGINT. */
    rv = uv_signal_init(s->loop, &s->sigint);
    if (rv != 0) {
        goto errAfterLoopInit;
    }
    s->sigint.data = s;

    /* Add a timer to periodically try to propose a new entry. */
    rv = uv_timer_init(s->loop, &s->timer);
    if (rv != 0) {
        goto errAfterSigintInit;
    }
    s->timer.data = s;

    /* Initialize the TCP-based RPC transport. */
    rv = raft_uv_tcp_init(&s->transport, s->loop);
    if (rv != 0) {
        goto errAfterTimerInit;
    }

    /* Initialize the libuv-based I/O backend. */
    rv = raft_uv_init(&s->io, s->loop, dir, &s->transport);
    if (rv != 0) {
        goto errAfterTcpInit;
    }

    /* Initialize the finite state machine. */
    rv = fsmInit(&s->fsm);
    if (rv != 0) {
        goto errAfterIoInit;
    }

    /* Save the server ID. */
    s->id = id;

    /* Initialize the default logger. */
    s->logger.impl = (void *)&s->id;
    s->logger.level = RAFT_INFO;
    s->logger.emit = emit;

    /* Render the address. */
    sprintf(s->address, "127.0.0.1:900%d", id);

    /* Initialize and start the engine, using the libuv-based I/O backend. */
    rv = raft_init(&s->raft, &s->io, &s->fsm, &s->logger, id, s->address);
    if (rv != 0) {
        goto errAfterFsmInit;
    }
    s->raft.data = s;

    /* Bootstrap the initial configuration if needed. */
    raft_configuration_init(&configuration);
    for (i = 0; i < N_SERVERS; i++) {
        char address[64];
        unsigned server_id = i + 1;
        sprintf(address, "127.0.0.1:900%d", server_id);
        rv = raft_configuration_add(&configuration, server_id, address, true);
        if (rv != 0) {
            goto errAfterRaftInit;
        }
    }
    rv = raft_bootstrap(&s->raft, &configuration);
    if (rv != 0 && rv != RAFT_CANTBOOTSTRAP) {
        goto errAfterConfigurationInit;
    }
    raft_configuration_close(&configuration);

    raft_set_snapshot_threshold(&s->raft, 1024);
    raft_set_snapshot_trailing(&s->raft, 8192);

    return 0;

errAfterConfigurationInit:
    raft_configuration_close(&configuration);
errAfterRaftInit:
    raft_close(&s->raft, NULL);
errAfterFsmInit:
    fsmClose(&s->fsm);
errAfterIoInit:
    raft_uv_close(&s->io);
errAfterTcpInit:
    raft_uv_tcp_close(&s->transport);
errAfterTimerInit:
    uv_close((struct uv_handle_s *)&s->timer, NULL);
errAfterSigintInit:
    uv_close((struct uv_handle_s *)&s->sigint, NULL);
errAfterLoopInit:
    uv_loop_delete(s->loop);
err:
    return rv;
}

/* Release the memory the raft instance and all its dependencies. */
static void serverClose(struct server *s)
{
    fsmClose(&s->fsm);
    raft_uv_close(&s->io);
    raft_uv_tcp_close(&s->transport);
    uv_loop_delete(s->loop);
}

/* Called after a request to apply a new command to the FSM has been
 * completed. */
static void applyCb(struct raft_apply *req, int status, void *result)
{
    struct server *s = req->data;
    int count;
    raft_free(req);
    if (status != 0) {
        if (status != RAFT_LEADERSHIPLOST) {
            emitf(s, RAFT_WARN, "fsm: apply error: %s", raft_strerror(status));
        }
        return;
    }
    count = *(int *)result;
    if (count % 100 == 0) {
        emitf(s, RAFT_INFO, "fsm: count %d", count);
    }
}

/* Called periodically every APPLY_RATE milliseconds. */
static void timerCb(uv_timer_t *timer, int status)
{
    struct server *s = timer->data;
    struct raft_buffer buf;
    struct raft_apply *req;
    int rv;

    if (s->raft.state != RAFT_LEADER) {
        return;
    }

    buf.len = sizeof(uint64_t);
    buf.base = raft_malloc(buf.len);
    if (buf.base == NULL) {
        emitf(s, RAFT_ERROR, "fsm: out of memory");
        return;
    }

    *(uint64_t *)buf.base = 1;

    req = raft_malloc(sizeof *req);
    if (req == NULL) {
        emitf(s, RAFT_ERROR, "fsm: out of memory");
        return;
    }
    req->data = s;

    rv = raft_apply(&s->raft, req, &buf, 1, applyCb);
    if (rv != 0) {
        emitf(s, RAFT_ERROR, "fsm: apply: %s", raft_strerror(rv));
        return;
    }
}

/* Start the example server. */
static int serverStart(struct server *s)
{
    int rv;

    rv = raft_start(&s->raft);
    if (rv != 0) {
        goto err;
    }
    rv = uv_signal_start(&s->sigint, sigintCb, SIGINT);
    if (rv != 0) {
        goto errAfterRaftStart;
    }
    rv = uv_timer_start(&s->timer, timerCb, 0, 125);
    if (rv != 0) {
        goto errAfterSigintStart;
    }

    /* Run the event loop until we receive SIGINT. */
    rv = uv_run(s->loop, UV_RUN_DEFAULT);
    if (rv != 0) {
        goto errAfterTimerStart;
    }

    return 0;

errAfterTimerStart:
    uv_timer_stop(&s->timer);
errAfterSigintStart:
    uv_signal_stop(&s->sigint);
errAfterRaftStart:
    raft_close(&s->raft, NULL);
err:
    uv_close((struct uv_handle_s *)&s->timer, NULL);
    uv_close((struct uv_handle_s *)&s->sigint, NULL);
    uv_run(s->loop, UV_RUN_NOWAIT);
    return rv;
}

int main(int argc, char *argv[])
{
    struct server server;
    const char *dir;
    unsigned id;
    int rv;

    if (argc != 3) {
        printf("usage: example-server <dir> <id>\n");
        return 1;
    }

    dir = argv[1];
    id = atoi(argv[2]);

    /* Initialize the server. */
    rv = serverInit(&server, dir, id);
    if (rv != 0) {
        goto err;
    }

    /* Run. */
    rv = serverStart(&server);
    if (rv != 0) {
        goto errAfterServerInit;
    }

    /* Clean up */
    serverClose(&server);

    return 0;

errAfterServerInit:
    serverClose(&server);
err:
    return rv;
}
