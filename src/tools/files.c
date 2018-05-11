// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2018, SecurActive.
 *
 * This file is part of Junkie.
 *
 * Junkie is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Junkie is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Junkie.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <assert.h>
#include "junkie/tools/files.h"
#include "junkie/tools/log.h"

int mkdir_all(char const *path, bool is_filename)
{
    SLOG(LOG_DEBUG, "mkdir %s", path);

    static __thread char filename[PATH_MAX];
    char *c;
    snprintf(filename, sizeof(filename), "%s", path);
    c = filename;
    if (!*c) {
        SLOG(LOG_ERR, "Empty string is not a correct path");
        return -1;
    }
    for (c = filename+1; *c; c++) {
        if ('/' == *c) {
            *c = '\0';
            if (-1 == mkdir(filename, 0755) && EEXIST != errno) {
mkdir_err:
                SLOG(LOG_ERR, "Cannot mkdir %s: %s", filename, strerror(errno));
                return -1;
            }
            *c = '/';
        }
    }

    if (! is_filename) {
        if (-1 == mkdir(filename, 0755) && EEXIST != errno) {
            goto mkdir_err;
        }
    }

    return 0;
}


static uid_t get_uid(const char * const user)
{
    assert(user);
    uid_t uid;

    errno = 0;
    struct passwd *u = getpwnam(user);
    if (u) {
        uid = u->pw_uid;
    } else {
        SLOG(LOG_ERR, "getpwnam: can't get the uid of '%s': %s", user, errno ? strerror(errno) : "No such user probably");
        uid = getuid(); // default one
    }

    return uid;
}

static gid_t get_gid(const char * const group)
{
    assert(group);
    gid_t gid;

    errno = 0;
    struct group *g = getgrnam(group);
    if (g) {
        gid = g->gr_gid;
    } else {
        SLOG(LOG_ERR, "getgrnam: can't get the uid of '%s': %s", group, errno ? strerror(errno) : "No such group probably");
        gid = getgid(); // default one
    }

    return gid;
}

int chusergroup(const char * const path, const char * const user, const char * const group)
{
    uid_t uid = user && user[0] != '\0' ? get_uid(user) : (uid_t)-1;
    gid_t gid = group && group[0] != '\0' ? get_gid(group) : (gid_t)-1;

    if (-1 == chown(path, uid, gid)) {
        SLOG(LOG_ERR, "chown: %s (path=%s, user=%s, group=%s)", strerror(errno), path, user, group);
        return -1;
    }

    return 0;
}

/*
 * File utilities, log common errors.
 */

int file_open(char const *file_name, int flags)
{
    int fd = open(file_name, flags, 0644);
    SLOG(LOG_DEBUG, "Opening file %s into fd %d", file_name, fd);
    if (fd < 0) {
        if (errno == ENOENT && flags & O_CREAT) {
            SLOG(LOG_DEBUG, "Creating missing path for %s", file_name);
            if (0 != mkdir_all(file_name, true)) return -1;
            return file_open(file_name, flags);
        }
        SLOG(errno == EEXIST && flags & O_EXCL ? LOG_DEBUG : LOG_ERR,
             "Cannot open file '%s': %s", file_name, strerror(errno));
        return -errno;
    }

    return fd;
}

void file_close(int fd)
{
    SLOG(LOG_DEBUG, "Closing fd %d", fd);
    if (0 != close(fd)) {
        SLOG(LOG_ERR, "Cannot close fd %d: %s", fd, strerror(errno));
        // keep going
    }
}

int file_unlink(char const *file_name)
{
    SLOG(LOG_DEBUG, "Unlinking file '%s'", file_name);

    if (0 != unlink(file_name)) {
        SLOG(LOG_ERR, "Cannot unlink %s: %s", file_name, strerror(errno));
        return -1;
    }

    return 0;
}

ssize_t file_seek(int fd, off_t offset, int whence)
{
    off_t sz = lseek(fd, offset, whence);
    if (sz == (off_t)-1) {
        SLOG(LOG_ERR, "Cannot lseek in fd %d: %s", fd, strerror(errno));
        return -1;
    }
    return sz;
}

ssize_t file_size(char const *file_name)
{
    int fd = file_open(file_name, O_RDONLY);
    if (fd < 0) return -1;

    off_t sz = file_seek(fd, 0, SEEK_END);
    if (sz == (off_t)-1) goto err1;

    file_close(fd);
    return sz;

err1:
    file_close(fd);
    return -1;
}

bool file_exists(char const *file_name)
{
    int fd = open(file_name, O_RDONLY, 0644);
    if (fd < 0) return false;
    file_close(fd);
    return true;
}

int file_write(int fd, void const *buf, size_t len)
{
    SLOG(LOG_DEBUG, "Writing %zu bytes onto fd %d", len, fd);
    size_t r = 0;

    while (r < len) {
        ssize_t ret = write(fd, buf+r, len-r);
        if (ret >= 0) {
            r += ret;
        } else if (errno != EINTR) {
            SLOG(LOG_ERR, "Cannot write %zu bytes on fd %d: %s", len, fd, strerror(errno));
            return -1;
        }
    }

    return 0;
}

int file_writev(int fd, struct iovec *iov, int iovcnt)
{
    SLOG(LOG_DEBUG, "Writing %d IOvectors onto fd %d", iovcnt, fd);

    while (1) {
        ssize_t ret = writev(fd, iov, iovcnt);
        if (ret < 0) {
            if (errno == EINTR) {
                ret = 0;    // retry
            } else {
                SLOG(LOG_ERR, "Cannot writev %d IOvectors onto fd %d: %s", iovcnt, fd, strerror(errno));
                return -1;
            }
        }
        while (iovcnt > 0 && (size_t)ret >= iov->iov_len) {
            ret -= iov->iov_len;
            iov ++;
            iovcnt --;
        }
        if (0 == iovcnt) break; // we are done
        iov->iov_base = iov->iov_base + ret;
        iov->iov_len -= (size_t)ret;
    }

    return 0;
}

ssize_t file_read(int fd, void *buf, size_t len)
{
    SLOG(LOG_DEBUG, "Reading %zu bytes from fd %d", len, fd);
    size_t r = 0;

    while (r < len) {
        ssize_t ret = read(fd, buf+r, len-r);
        if (ret > 0) {
            r += ret;
        } else if (ret == 0) {
            SLOG(LOG_DEBUG, "EOF reached while reading %zu bytes on fd %d (%zu bytes missing)", len, fd, (len-r));
            break;
        } else if (errno != EINTR) {
            SLOG(LOG_ERR, "Cannot read %zu bytes on fd %d: %s", len, fd, strerror(errno));
            return -1;
        }
    }

    return r;
}

void *file_load(char const *file_name, size_t *len_)
{
    assert(file_name);
    SLOG(LOG_DEBUG, "Loading content of file '%s'", file_name);
    ssize_t len = file_size(file_name);
    if (len < 0) return NULL;
    if (len_) *len_ = len;

    if (len == 0) return NULL;

    char *buf = malloc(len+1);
    if (! buf) {
        SLOG(LOG_ERR, "Cannot alloc for reading %zu bytes", len);
        return NULL;
    }

    int fd = file_open(file_name, O_RDONLY);
    if (fd < 0) goto err1;

    if (len != file_read(fd, buf, len)) goto err2;
    buf[len] = '\0';

    file_close(fd);
    return buf;

err2:
    file_close(fd);
err1:
    free(buf);
    return NULL;
}

int file_foreach_line(char const *filename, int (*cb)(char *line, size_t len, va_list), ...)
{
    int ret = -1;
    va_list ap;
    va_start(ap, cb);

    int fd = file_open(filename, O_RDONLY);
    if (fd < 0) goto quit;

    static __thread char buf[2047+1];
    ssize_t read_len;
    size_t already_in = 0;
    bool skip = false;
    do {
        read_len = file_read(fd, buf + already_in, sizeof(buf)-1 - already_in);
        if (read_len + already_in == 0) break;

        buf[already_in + read_len] = '\0';
        char *nl = strchr(buf, '\n');
        bool skip_next = false;
        if (! nl) {
            SLOG(LOG_ERR, "Line too long, truncating");
            nl = buf + already_in + read_len;
            skip_next = true;
        } else {
            *nl = '\0';
        }

        if (! skip) {
            va_list aq;
            va_copy(aq, ap);
            ret = cb(buf, nl - buf, aq);
            va_end(aq);
            if (ret != 0) break;
        }

        size_t mv_size = already_in + read_len - (nl+1-skip_next-buf);
        memmove(buf, nl+1, mv_size);
        already_in = mv_size;
        skip = skip_next;
    } while (1);

    file_close(fd);
quit:
    va_end(ap);
    return ret;
}

off_t file_offset(int fd)
{
    off_t ret = lseek(fd, 0, SEEK_CUR);
    if ((off_t)-1 == ret) {
        SLOG(LOG_ERR, "Cannot lseek fd %d: %s", fd, strerror(errno));
    }
    return ret;
}

int chdir_for_file(char const *dir, bool is_filename)
{
    char *redir;
    if (is_filename) {
        redir = tempstr_printf("%s", dir);
        char *last_slash = redir;
        for (char *c = redir; *c; c++) if (*c == '/') last_slash = c;
        *last_slash = '\0';
    } else {
        redir = (char *)dir;
    }

    SLOG(LOG_DEBUG, "chdir into '%s'", redir);
    if (redir[0] == '\0') return 0;

    if (0 != chdir(redir)) {
        SLOG(LOG_ERR, "Cannot chdir(%s): %s", redir, strerror(errno));
        return -1;
    }

    return 0;
}

void set_rcvbuf(int fd, size_t sz_)
{
    SLOG(LOG_DEBUG, "Setting receive buffer size to %zu", sz_);
    int sz = sz_;
    if (0 != setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz))) {
        SLOG(LOG_ERR, "Cannot set receive buffer size to %zu bytes: %s", sz_, strerror(errno));
    }
}

/*
 * Init
 */

static unsigned inited;
void files_init(void)
{
    if (inited++) return;
}

void files_fini(void)
{
    if (--inited) return;
}
