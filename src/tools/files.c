// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2010, SecurActive.
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
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <assert.h>
#include <junkie/tools/files.h>
#include <junkie/tools/log.h>
#include <junkie/tools/mallocer.h>

static char const Id[] = "$Id: 149f17cbcc369a7832303bf390c768771b93b5ce $";

int mkdir_all(char const *path, bool is_filename)
{
    SLOG(LOG_DEBUG, "mkdir %s", path);

    char filename[PATH_MAX];    // not const
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
        SLOG(LOG_ERR, "getpwnam: can't get the uid of '%s': %s", user, strerror(errno));
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
        SLOG(LOG_ERR, "getgrnam: can't get the uid of '%s': %s", group, strerror(errno));
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
        SLOG(LOG_ERR, "Cannot open file '%s': %s", file_name, strerror(errno));
        return -1;
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

int file_write(int fd, void const *buf, size_t len)
{
    SLOG(LOG_DEBUG, "Writing %zu bytes onto fd %d", len, fd);
    size_t r = 0;

    while (r < len) {
        ssize_t ret = write(fd, buf+r, len-r);
        if (ret >= 0) {
            r += ret;
        } else if (errno != EINTR) {
            SLOG(LOG_ERR, "Cannot read %zu bytes on fd %d: %s", len, fd, strerror(errno));
            return -1;
        }
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

    MALLOCER(file_content);

    char *buf = MALLOC(file_content, len+1);
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
    FREE(buf);
    return NULL;
}

int file_foreach_line(char const *filename, int (*cb)(char *line, size_t len, va_list), ...)
{
    int ret = -1;
    va_list ap;
    va_start(ap, cb);

    int fd = file_open(filename, O_RDONLY);
    if (fd < 0) goto quit;

    char buff[2047+1];
    ssize_t read_len;
    size_t already_in = 0;
    bool skip = false;
    do {
        read_len = file_read(fd, buff + already_in, sizeof(buff)-1 - already_in);
        if (read_len + already_in == 0) break;

        buff[already_in + read_len] = '\0';
        char *nl = strchr(buff, '\n');
        bool skip_next = false;
        if (! nl) {
            SLOG(LOG_ERR, "Line too long, truncating");
            nl = buff + already_in + read_len;
            skip_next = true;
        } else {
            *nl = '\0';
        }

        if (! skip) {
            va_list aq;
            va_copy(aq, ap);
            ret = cb(buff, nl - buff, aq);
            va_end(aq);
            if (ret != 0) break;
        }

        size_t mv_size = already_in + read_len - (nl+1-skip_next-buff);
        memmove(buff, nl+1, mv_size);
        already_in = mv_size;
        skip = skip_next;
    } while (1);

    file_close(fd);
quit:
    va_end(ap);
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
