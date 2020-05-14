#include <string.h>

#include "assert.h"
#include "uv.h"

#if UV_CCOWFSIO_ENABLED
#include <dirent.h>
#endif

#if 0
#define tracef(...) Tracef(uv->tracer, __VA_ARGS__)
#else
#define tracef(...)
#endif

static const char *uvListIgnored[] = {".", "..", "metadata1", "metadata2",
                                      NULL};

/* Return true if the given filename should be ignored. */
static bool uvListShouldIgnore(const char *filename)
{
    const char **cursor = uvListIgnored;
    bool result = false;
    if (strlen(filename) >= UV__FILENAME_LEN) {
        return true;
    }
    while (*cursor != NULL) {
        if (strcmp(filename, *cursor) == 0) {
            result = true;
            break;
        }
        cursor++;
    }
    return result;
}

#if UV_CCOWFSIO_ENABLED
int UvList(struct uv *uv,
           struct uvSnapshotInfo *snapshots[],
           size_t *n_snapshots,
           struct uvSegmentInfo *segments[],
           size_t *n_segments,
           char *errmsg)
{
    struct dirent **dirents;
    uint64_t i, n_dirents;
    int rv;

    rv = UvOsScanDir(uv->dir, &dirents, &n_dirents, errmsg);
    if (rv != 0) {
        ErrMsgPrintf(errmsg, "scan data directory %s: %s", uv->dir,
            uv_strerror(uv__new_artificial_error(rv)));
        return RAFT_IOERR;
    }

    *snapshots = NULL;
    *n_snapshots = 0;

    *segments = NULL;
    *n_segments = 0;

    for (i = 0; i < n_dirents; i++) {
        struct dirent *entry = dirents[i];
        const char *filename = entry->d_name;
        bool appended;

        /* If an error occurred while processing a preceeding entry or if we
         * know that this is not a segment filename, just free it and skip to
         * the next one. */
        if (rv != 0 || uvListShouldIgnore(filename)) {
            if (rv == 0) {
                tracef(uv, "ignore %s", filename);
            }
            free(entry);
            continue;
        }

        /* Append to the snapshot list if it's a snapshot metadata filename and
         * a valid associated snapshot file exists. */
        rv = UvSnapshotInfoAppendIfMatch(uv, filename, snapshots, n_snapshots,
                                         &appended);
        if (appended || rv != 0) {
            if (rv == 0) {
                tracef("snapshot %s", filename);
            }
            free(entry);
            continue;
        }

        /* Append to the segment list if it's a segment filename */
        rv = uvSegmentInfoAppendIfMatch(filename, segments, n_segments,
                                        &appended);
        if (appended || rv != 0) {
            if (rv == 0) {
                tracef("segment %s", filename);
            }
            free(entry);
            continue;
        }

        tracef("ignore %s", filename);
    }
    free(dirents);

    if (rv != 0 && *segments != NULL) {
        raft_free(*segments);
    }

    if (*snapshots != NULL) {
        UvSnapshotSort(*snapshots, *n_snapshots);
    }

    if (*segments != NULL) {
        uvSegmentSort(*segments, *n_segments);
    }

    return rv;
}
#else
typedef enum {
    UV_DIRENT_UNKNOWN,
    UV_DIRENT_FILE,
    UV_DIRENT_DIR,
    UV_DIRENT_LINK,
    UV_DIRENT_FIFO,
    UV_DIRENT_SOCKET,
    UV_DIRENT_CHAR,
    UV_DIRENT_BLOCK
} uv_dirent_type_t;

typedef struct uv_dirent_s {
    const char* name;
    uv_dirent_type_t type;
} uv_dirent_t;

int UvList(struct uv *uv,
           struct uvSnapshotInfo *snapshots[],
           size_t *n_snapshots,
           struct uvSegmentInfo *segments[],
           size_t *n_segments,
           char *errmsg)
{
    struct uv_fs_s req;
    struct uv_dirent_s entry;
    int n;
    int i;
    int rv;
    int rv2;

    n = uv_fs_scandir(NULL, &req, uv->dir, 0, NULL);
    if (n < 0) {
        ErrMsgPrintf(errmsg, "scan data directory: %s",
            uv_strerror(uv__new_artificial_error(n)));
        return RAFT_IOERR;
    }

    *snapshots = NULL;
    *n_snapshots = 0;

    *segments = NULL;
    *n_segments = 0;

    rv = 0;

    for (i = 0; i < n; i++) {
        const char *filename;
        bool appended;

        rv = uv_fs_scandir_next(&req, &entry);
        assert(rv == 0); /* Can't fail in libuv */

        filename = entry.name;

        /* If an error occurred while processing a preceeding entry or if we
         * know that this is not a segment filename, just free it and skip to
         * the next one. */
        if (rv != 0 || uvListShouldIgnore(filename)) {
            if (rv == 0) {
                tracef("ignore %s", filename);
            }
            continue;
        }

        /* Append to the snapshot list if it's a snapshot metadata filename and
         * a valid associated snapshot file exists. */
        rv = UvSnapshotInfoAppendIfMatch(uv, filename, snapshots, n_snapshots,
                                         &appended);
        if (appended || rv != 0) {
            if (rv == 0) {
                tracef("snapshot %s", filename);
            }
            continue;
        }

        /* Append to the segment list if it's a segment filename */
        rv = uvSegmentInfoAppendIfMatch(entry.name, segments, n_segments,
                                        &appended);
        if (appended || rv != 0) {
            if (rv == 0) {
                tracef("segment %s", filename);
            }
            continue;
        }

        tracef("ignore %s", filename);
    }

    rv2 = uv_fs_scandir_next(&req, &entry);
    assert(rv2 == UV_EOF);

    if (rv != 0 && *segments != NULL) {
        raft_free(*segments);
    }

    if (*snapshots != NULL) {
        UvSnapshotSort(*snapshots, *n_snapshots);
    }

    if (*segments != NULL) {
        uvSegmentSort(*segments, *n_segments);
    }

    return rv;
}
#endif /* UV_CCOWFSIO_ENABLED */

#undef tracef
