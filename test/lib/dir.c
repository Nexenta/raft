#include "dir.h"

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#include "../../src/uv_os.h"

#define SEP "/"
#define TEMPLATE "raft-test-XXXXXX"

#define TEST_DIR_TEMPLATE "./tmp/%s/raft-test-XXXXXX"

char *test_dir_all[] = {"tmpfs", "ext4", "edgefs",
                        "btrfs",
                        "xfs",
                        "zfs",
                        NULL};

char *test_dir_tmpfs[] = {"tmpfs", NULL};

char *test_dir_btrfs[] = {"btrfs", NULL};

char *test_dir_zfs[] = {"zfs", NULL};

char *test_dir_aio[] = {
    "btrfs",
    "ext4",
    "xfs",
    NULL};

char *test_dir_no_aio[] = {"tmpfs",
                           "zfs",
                           NULL};

MunitParameterEnum dir_tmpfs_params[] = {
    {TEST_DIR_FS, test_dir_tmpfs},
    {NULL, NULL},
};

MunitParameterEnum dir_btrfs_params[] = {
    {TEST_DIR_FS, test_dir_btrfs},
    {NULL, NULL},
};

MunitParameterEnum dir_zfs_params[] = {
    {TEST_DIR_FS, test_dir_zfs},
    {NULL, NULL},
};

MunitParameterEnum dir_all_params[] = {
    {TEST_DIR_FS, test_dir_all},
    {NULL, NULL},
};

MunitParameterEnum dir_aio_params[] = {
    {TEST_DIR_FS, test_dir_aio},
    {NULL, NULL},
};

MunitParameterEnum dir_no_aio_params[] = {
    {TEST_DIR_FS, test_dir_no_aio},
    {NULL, NULL},
};

/* Create a temporary directory in the given parent directory. */
static char *mkTempDir(const char *parent)
{
    char *dir;
    if (parent == NULL) {
        return NULL;
    }
    dir = munit_malloc(strlen(parent) + strlen(SEP) + strlen(TEMPLATE) + 1);
    sprintf(dir, "%s%s%s", parent, SEP, TEMPLATE);
    if (mkdtemp(dir) == NULL) {
        munit_error(strerror(errno));
    }
    return dir;
}

void *setupDir(MUNIT_UNUSED const MunitParameter params[],
               MUNIT_UNUSED void *user_data)
{
    const char *fs = munit_parameters_get(params, TEST_DIR_FS);
    if (fs == NULL) {
        if (getenv("RAFT_TMP_EDGEFS"))
	    return getenv("RAFT_TMP_EDGEFS");
        return mkTempDir("/tmp");
    } else if (strcmp(fs, "tmpfs") == 0) {
        return setupTmpfsDir(params, user_data);
    } else if (strcmp(fs, "edgefs") == 0) {
        return getenv("RAFT_TMP_EDGEFS");
    } else if (strcmp(fs, "ext4") == 0) {
        return setupExt4Dir(params, user_data);
    } else if (strcmp(fs, "btrfs") == 0) {
        return setupBtrfsDir(params, user_data);
    } else if (strcmp(fs, "zfs") == 0) {
        return setupZfsDir(params, user_data);
    } else if (strcmp(fs, "xfs") == 0) {
        return setupXfsDir(params, user_data);
    }
    munit_errorf("Unsupported file system %s", fs);
    return NULL;
}

void *setupTmpfsDir(MUNIT_UNUSED const MunitParameter params[],
                    MUNIT_UNUSED void *user_data)
{
    return mkTempDir(getenv("RAFT_TMP_TMPFS"));
}

void *setupExt4Dir(MUNIT_UNUSED const MunitParameter params[],
                   MUNIT_UNUSED void *user_data)
{
    return mkTempDir(getenv("RAFT_TMP_EXT4"));
}

void *setupBtrfsDir(MUNIT_UNUSED const MunitParameter params[],
                    MUNIT_UNUSED void *user_data)
{
    return mkTempDir(getenv("RAFT_TMP_BTRFS"));
}

void *setupZfsDir(MUNIT_UNUSED const MunitParameter params[],
                  MUNIT_UNUSED void *user_data)
{
    return mkTempDir(getenv("RAFT_TMP_ZFS"));
}

void *setupXfsDir(MUNIT_UNUSED const MunitParameter params[],
                  MUNIT_UNUSED void *user_data)
{
    return mkTempDir(getenv("RAFT_TMP_XFS"));
}

char *test_dir_setup(const MunitParameter params[])
{
    return setupDir(params, NULL);
}

#if UV_CCOWFSIO_ENABLED

#include "src/uv_ccowfsio_file.h"

extern int
ccow_fsio_find_export(char *cid, size_t cid_size, char *tid, size_t tid_size,
    char *bid, size_t bid_size, ci_t ** out_ci);

/* Wrapper around remove(), compatible with ntfw. */
static int removeFn(const char *path,
                    MUNIT_UNUSED const struct stat *sbuf,
                    MUNIT_UNUSED int type,
                    MUNIT_UNUSED struct FTW *ftwb)
{
    return remove(path);
}

static int
recursive_delete(inode_t parent, fsio_dir_entry *dir_entry, uint64_t count, void *ptr)
{
	uint64_t i;
	ci_t *ci = ptr;

	for (i=0; i< count; i++) {
		if (dir_entry[i].name[0] == '.' && (dir_entry[i].name[1] == '\0' ||
			    (dir_entry[i].name[1] == '.' && dir_entry[i].name[2] == '\0')))
			continue;

		if (ccow_fsio_is_dir(ci, dir_entry[i].inode)) {
			bool eof;
			ccow_fsio_readdir_cb4(ci, dir_entry[i].inode, recursive_delete, 0, NULL, &eof);
		}
		if (dir_entry[i].inode != CCOW_FSIO_ROOT_INODE &&
		    dir_entry[i].inode != CCOW_FSIO_LOST_FOUND_DIR_INODE) {
			int err = ccow_fsio_delete(ci, parent, dir_entry[i].name);
			munit_assert_int(err, ==, 0);
		}
	}

	return (0);
}

void tearDownDir(void *data)
{
	if (data == NULL) {
		return;
	}

	inode_t di;
	ci_t *ci = findFSExportByDir((char*)data, &di);
	munit_assert_not_null(ci);

	bool eof;
	int err = ccow_fsio_readdir_cb4(ci, di, recursive_delete, 0, ci, &eof);
	munit_assert_int(err, ==, 0);
}

void test_dir_tear_down(char *dir)
{
    tearDownDir(dir);
}

static void skip_free(void *ptr) {}

void test_dir_write_file(const char *dir,
                         const char *filename,
                         const void *buf,
                         const size_t n)
{
	inode_t di, fi;

	ci_t *ci = findFSExportByDir((char*)dir, &di);
	munit_assert_not_null(ci);

	int err;
	err = ccow_fsio_touch(ci, di, (char*)filename, 0600, 0, 0, &fi);
	if (err == EEXIST) err = 0;
	munit_assert_int(err, ==, 0);

	ccow_fsio_file_t *f;
	err = ccow_fsio_openi(ci, fi, &f, O_RDWR);
	if (err) {
	}

	if (buf && n > 0) {
		size_t write_amount = 0;
		ccow_fsio_write_free_set(f, skip_free);
		err = ccow_fsio_write(f, 0, n, (void *)buf, &write_amount);
		if (err == 0)
			ccow_fsio_flush(f);
		munit_assert_int(err, ==, 0);
		munit_assert_int(write_amount, ==, n);
	}

	ccow_fsio_close(f);
}

void test_dir_write_file_with_zeros(const char *dir,
                                    const char *filename,
                                    const size_t n)
{
    void *buf;

    buf = munit_malloc(n);
    memset(buf, 0, n);

    test_dir_write_file(dir, filename, buf, n);

    free(buf);
}

void test_dir_append_file(const char *dir,
                          const char *filename,
                          const void *buf,
                          const size_t n)
{
	struct stat sb;
	uvPath path;
	char *root = NULL, *p;
	int err;
	inode_t di, fi;

	ci_t *ci = findFSExportByDir((char*)dir, &di);
	munit_assert_not_null(ci);

	/* Get tenant */
	p = strchr(dir, '/');
	/* Get bucket */
	if (p)
		p = strchr(p+1,'/');
	/* Get root */
	if (p)
		root = strchr(p+1,'/');
	uvJoin(root, filename, path);

	assert(path[0] == '/');
	err = ccow_fsio_find(ci, path, &fi);
	munit_assert_int(err, ==, 0);

	err = ccow_fsio_get_file_stat(ci, fi, &sb);
	munit_assert_int(err, ==, 0);

	ccow_fsio_file_t *f;
	err = ccow_fsio_open(ci, path, &f, O_RDWR | O_APPEND);
	munit_assert_int(err, ==, 0);

	munit_assert_int(n, !=, 0);
	size_t write_amount = 0;
	ccow_fsio_write_free_set(f, skip_free);
	err = ccow_fsio_write(f, sb.st_size, n, (void *)buf, &write_amount);
	munit_assert_int(err, ==, 0);
	munit_assert_int(write_amount, ==, n);
}

void test_dir_overwrite_file(const char *dir,
                             const char *filename,
                             const void *buf,
                             const size_t n,
                             const off_t whence)
{
	uvPath path;
	char *root = NULL, *p;
	int err;
	inode_t di, fi;

	ci_t *ci = findFSExportByDir((char*)dir, &di);
	munit_assert_not_null(ci);

	/* Get tenant */
	p = strchr(dir, '/');
	/* Get bucket */
	if (p)
		p = strchr(p+1,'/');
	/* Get root */
	if (p)
		root = strchr(p+1,'/');
	uvJoin(root, filename, path);

	ccow_fsio_file_t *f;
	err = ccow_fsio_open(ci, path, &f, O_RDWR);
	munit_assert_int(err, ==, 0);

	size_t write_amount = 0;
	ccow_fsio_write_free_set(f, skip_free);
	err = ccow_fsio_write(f, whence, n, (void *)buf, &write_amount);
	if (err == 0)
		ccow_fsio_flush(f);
	munit_assert_int(err, ==, 0);
	munit_assert_int(write_amount, ==, n);

	ccow_fsio_close(f);
}

void test_dir_overwrite_file_with_zeros(const char *dir,
                                        const char *filename,
                                        const size_t n,
                                        const off_t whence)
{
    void *buf;

    buf = munit_malloc(n);
    memset(buf, 0, n);

    test_dir_overwrite_file(dir, filename, buf, n, whence);

    free(buf);
}

/*
 * TODO: This is emulation. Replace with real truncate which releases the
 * disk space as well.
 */
void test_dir_truncate_file(const char *dir,
                            const char *filename,
                            const size_t n)
{
	char dpath[UV__PATH_MAX_LEN], *root;
	uvPath path;

	strcpy(dpath, dir);
	char *subdir = NULL;
	char *p = strrchr(dpath, '/');
	if (p) {
		*p = 0;
		subdir = p+1;
	}
	inode_t di, fi;
	ci_t *ci = findFSExportByDir((char*)dpath, &di);
	munit_assert_not_null(ci);
	munit_assert(di != 0);

	strcpy(dpath, dir);
	/* Get tenant */
	p = strchr(dpath, '/');
	/* Get bucket */
	if (p)
		p = strchr(p+1,'/');
	/* Get root */
	if (p)
		root = strchr(p+1,'/');
	p = strrchr(dpath, '/');
	if (p)
		subdir = p+1;
	if (subdir) {
		struct stat sb;
		inode_t ino;
		uvJoin(root, filename, path);
		assert(path[0] == '/');
		int err = ccow_fsio_find(ci, path, &ino);
		if (err == 0) {
			err = ccow_fsio_get_file_stat(ci, ino, &sb);
			if (err == 0) {
				sb.st_size = n;
				ccow_fsio_set_file_stat(ci, ino, &sb);
				ccow_fsio_file_t *file;
				err = ccow_fsio_open(ci, path,
						&file, O_RDONLY);
				if (err == 0)
					ccow_fsio_flush(file);
			}
		}
	}
}

void test_dir_read_file(const char *dir,
                        const char *filename,
                        void *buf,
                        const size_t n)
{
	int err;
	inode_t di, fi;
	ccow_fsio_file_t *f;
	ci_t *ci = findFSExportByDir((char*)dir, &di);
	munit_assert_not_null(ci);
	err = ccow_fsio_lookup(ci, di, (char*)filename, &fi);
	munit_assert(err == 0);
	err = ccow_fsio_openi(ci, fi, &f, O_RDONLY);
	munit_assert(err == 0);
	size_t read_amount;
	int eof;
	err = ccow_fsio_read(f, 0, n, buf, &read_amount, &eof);
	munit_assert(err == 0 && read_amount == n);
	err = ccow_fsio_close(f);
	munit_assert(err == 0);
}

bool test_dir_exists(const char *dir)
{
	char dpath[UV__PATH_MAX_LEN];
	strcpy(dpath, dir);
	char *subdir = NULL;
	char *p = strrchr(dpath, '/');
	if (p) {
		*p = 0;
		subdir = p+1;
	}
	inode_t di, fi;
	ci_t *ci = findFSExportByDir((char*)dpath, &di);
	munit_assert_not_null(ci);
	munit_assert(di != 0);
	if (!subdir)
		return true;
	int err = ccow_fsio_lookup(ci, di, (char*)subdir, &fi);
	munit_assert(err == 0 || err == ENOENT);
	return err == 0;
}

void test_dir_unexecutable(const char *dir)
{
	char dpath[UV__PATH_MAX_LEN], *root;
	strcpy(dpath, dir);
	char *subdir = NULL;
	char *p = strrchr(dpath, '/');
	if (p) {
		*p = 0;
		subdir = p+1;
	}
	inode_t di, fi;
	ci_t *ci = findFSExportByDir((char*)dpath, &di);
	munit_assert_not_null(ci);
	munit_assert(di != 0);

	strcpy(dpath, dir);
	/* Get tenant */
	p = strchr(dpath, '/');
	/* Get bucket */
	if (p)
		p = strchr(p+1,'/');
	/* Get root */
	if (p)
		root = strchr(p+1,'/');
	p = strrchr(dpath, '/');
	if (p)
		subdir = p+1;
	if (subdir) {
		struct stat sb;
		inode_t ino;
		assert(root[0] == '/');
		int err = ccow_fsio_find(ci, root, &ino);
		if (err == 0) {
			err = ccow_fsio_get_file_stat(ci, ino, &sb);
			if (err == 0) {
				sb.st_mode = 0;
				ccow_fsio_set_file_stat(ci, ino, &sb);
			}
		}
	}
}

void test_dir_unreadable_file(const char *dir, const char *filename)
{
	char dpath[UV__PATH_MAX_LEN], *root;
	strcpy(dpath, dir);
	char *subdir = NULL;
	char *p = strrchr(dpath, '/');
	if (p) {
		*p = 0;
		subdir = p+1;
	}
	inode_t di, fi;
	ci_t *ci = findFSExportByDir((char*)dpath, &di);
	munit_assert_not_null(ci);
	munit_assert(di != 0);

	strcpy(dpath, dir);
	/* Get tenant */
	p = strchr(dpath, '/');
	/* Get bucket */
	if (p)
		p = strchr(p+1,'/');
	/* Get root */
	if (p)
		root = strchr(p+1,'/');
	p = strrchr(dpath, '/');
	if (p)
		subdir = p+1;
	if (subdir) {
		struct stat sb;
		inode_t ino, fino;
		assert(root[0] == '/');
		int err = ccow_fsio_find(ci, root, &ino);
		munit_assert (err == 0);
		err = ccow_fsio_lookup(ci, ino, filename, &fino);
		munit_assert (err == 0);
		err = ccow_fsio_get_file_stat(ci, fino, &sb);
		if (err == 0) {
			sb.st_mode = 0;
			ccow_fsio_set_file_stat(ci, fino, &sb);
		}
	}
}

bool test_dir_has_file(const char *dir, const char *filename)
{
	inode_t di, fi;
	ci_t *ci = findFSExportByDir((char*)dir, &di);
	munit_assert_not_null(ci);
	int err = ccow_fsio_lookup(ci, di, (char*)filename, &fi);
	munit_assert(err == 0 || err == ENOENT);
	return err == 0;
}

void test_dir_fill(const char *dir, const size_t n)
{
}


#else

/* Join the given @dir and @filename into @path. */
static void joinPath(const char *dir, const char *filename, char *path)
{
    strcpy(path, dir);
    strcat(path, "/");
    strcat(path, filename);
}

/* Wrapper around remove(), compatible with ntfw. */
static int removeFn(const char *path,
                    MUNIT_UNUSED const struct stat *sbuf,
                    MUNIT_UNUSED int type,
                    MUNIT_UNUSED struct FTW *ftwb)
{
    return remove(path);
}

void tearDownDir(void *data)
{
    char *dir = data;
    int rv;

    if (dir == NULL) {
        return;
    }

    rv = chmod(dir, 0755);
    munit_assert_int(rv, ==, 0);

    rv = nftw(dir, removeFn, 10, FTW_DEPTH | FTW_MOUNT | FTW_PHYS);
    munit_assert_int(rv, ==, 0);

    free(dir);
}

void test_dir_tear_down(char *dir)
{
    tearDownDir(dir);
}

void test_dir_write_file(const char *dir,
                         const char *filename,
                         const void *buf,
                         const size_t n)
{
    char path[256];
    int fd;
    int rv;

    joinPath(dir, filename, path);

    fd = open(path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    munit_assert_int(fd, !=, -1);

    rv = write(fd, buf, n);
    munit_assert_int(rv, ==, n);

    close(fd);
}

void test_dir_write_file_with_zeros(const char *dir,
                                    const char *filename,
                                    const size_t n)
{
    void *buf = munit_malloc(n);

    test_dir_write_file(dir, filename, buf, n);

    free(buf);
}

void test_dir_append_file(const char *dir,
                          const char *filename,
                          const void *buf,
                          const size_t n)
{
    char path[256];
    int fd;
    int rv;

    joinPath(dir, filename, path);

    fd = open(path, O_APPEND | O_RDWR, S_IRUSR | S_IWUSR);

    munit_assert_int(fd, !=, -1);

    rv = write(fd, buf, n);
    munit_assert_int(rv, ==, n);

    close(fd);
}

void test_dir_overwrite_file(const char *dir,
                             const char *filename,
                             const void *buf,
                             const size_t n,
                             const off_t whence)
{
    char path[256];
    int fd;
    int rv;
    off_t size;

    joinPath(dir, filename, path);

    fd = open(path, O_RDWR, S_IRUSR | S_IWUSR);

    munit_assert_int(fd, !=, -1);

    /* Get the size of the file */
    size = lseek(fd, 0, SEEK_END);

    if (whence == 0) {
        munit_assert_int(size, >=, n);
        lseek(fd, 0, SEEK_SET);
    } else if (whence > 0) {
        munit_assert_int(whence, <=, size);
        munit_assert_int(size - whence, >=, n);
        lseek(fd, whence, SEEK_SET);
    } else {
        munit_assert_int(-whence, <=, size);
        munit_assert_int(-whence, >=, n);
        lseek(fd, whence, SEEK_END);
    }

    rv = write(fd, buf, n);
    munit_assert_int(rv, ==, n);

    close(fd);
}

void test_dir_overwrite_file_with_zeros(const char *dir,
                                        const char *filename,
                                        const size_t n,
                                        const off_t whence)
{
    void *buf;

    buf = munit_malloc(n);
    memset(buf, 0, n);

    test_dir_overwrite_file(dir, filename, buf, n, whence);

    free(buf);
}

void test_dir_truncate_file(const char *dir,
                            const char *filename,
                            const size_t n)
{
    char path[256];
    int fd;
    int rv;

    joinPath(dir, filename, path);

    fd = open(path, O_RDWR, S_IRUSR | S_IWUSR);

    munit_assert_int(fd, !=, -1);

    rv = ftruncate(fd, n);
    munit_assert_int(rv, ==, 0);

    close(fd);
}

void test_dir_read_file(const char *dir,
                        const char *filename,
                        void *buf,
                        const size_t n)
{
    char path[256];
    int fd;
    int rv;

    joinPath(dir, filename, path);

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        munit_logf(MUNIT_LOG_ERROR, "read file '%s': %s", path,
                   strerror(errno));
    }

    rv = read(fd, buf, n);
    munit_assert_int(rv, ==, n);

    close(fd);
}

bool test_dir_exists(const char *dir)
{
    struct stat sb;
    int rv;

    rv = stat(dir, &sb);
    if (rv == -1) {
        munit_assert_int(errno, ==, ENOENT);
        return false;
    }

    return true;
}

void test_dir_unexecutable(const char *dir)
{
    int rv;

    rv = chmod(dir, 0);
    munit_assert_int(rv, ==, 0);
}

void test_dir_unreadable_file(const char *dir, const char *filename)
{
    char path[256];
    int rv;

    joinPath(dir, filename, path);

    rv = chmod(path, 0);
    munit_assert_int(rv, ==, 0);
}

bool test_dir_has_file(const char *dir, const char *filename)
{
    char path[256];
    int fd;

    joinPath(dir, filename, path);

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        munit_assert_int(errno, ==, ENOENT);
        return false;
    }

    close(fd);

    return true;
}

void test_dir_fill(const char *dir, const size_t n)
{
    char path[256];
    const char *filename = ".fill";
    struct statvfs fs;
    size_t size;
    int fd;
    int rv;

    rv = statvfs(dir, &fs);
    munit_assert_int(rv, ==, 0);

    size = fs.f_bsize * fs.f_bavail;

    if (n > 0) {
        munit_assert_int(size, >=, n);
    }

    joinPath(dir, filename, path);

    fd = open(path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    munit_assert_int(fd, !=, -1);

    rv = posix_fallocate(fd, 0, size);
    munit_assert_int(rv, ==, 0);

    /* If n is zero, make sure any further write fails with ENOSPC */
    if (n == 0) {
        char buf[4096];
        int i;

        rv = lseek(fd, 0, SEEK_END);
        munit_assert_int(rv, !=, -1);

        for (i = 0; i < 40; i++) {
            rv = write(fd, buf, sizeof buf);
            if (rv < 0) {
                break;
            }
        }

        munit_assert_int(rv, ==, -1);
        munit_assert_int(errno, ==, ENOSPC);
    }

    close(fd);
}

#endif

void test_aio_fill(aio_context_t *ctx, unsigned n)
{
    char buf[256];
    int fd;
    int rv;
    int limit;
    int used;
    char errmsg[2048];

    /* Figure out how many events are available. */
    fd = open("/proc/sys/fs/aio-max-nr", O_RDONLY);
    munit_assert_int(fd, !=, -1);

    rv = read(fd, buf, sizeof buf);
    munit_assert_int(rv, !=, -1);

    close(fd);

    limit = atoi(buf);

    /* Figure out how many events are in use. */
    fd = open("/proc/sys/fs/aio-nr", O_RDONLY);
    munit_assert_int(fd, !=, -1);

    rv = read(fd, buf, sizeof buf);
    munit_assert_int(rv, !=, -1);

    close(fd);

    used = atoi(buf);

    rv = uvIoSetup(limit - used - n, ctx, errmsg);
    munit_assert_int(rv, ==, 0);
}

void test_aio_destroy(aio_context_t ctx)
{
    char errmsg[2048];
    int rv;

    rv = uvIoDestroy(ctx, errmsg);
    munit_assert_int(rv, ==, 0);
}
