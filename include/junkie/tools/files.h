// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef FILE_H_100412
#define FILE_H_100412
#include <stdbool.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>

/** @file
 * @brief Some utilities to access the file system, with common errors handled or logged.
 */

/** Creates all required directory (similar to mkdir -p).
 * @param is_filename tells weither given path is a file or a directory
 * @returns -1 on error
 */
int mkdir_all(char const *, bool is_filename);

/** Change the permissions for a file.
 * @param path the file name
 * @param user the user name (will not be changed if NULL)
 * @param group the group name (will not be changed if NULL)
 * @returns 0 on success, -1 on error.
 */
int chusergroup(const char * const path, const char * const user, const char * const group);

/** Open a file, logging on error.
 * @returns -1 on error.
 */
int file_open(char const *file_name, int flags);

/// Close a file, logging on error.
void file_close(int fd);

/// Unlink a file
int file_unlink(char const *file_name);

/// Returns the file size, logging on error.
ssize_t file_size(char const *file_name);

/// Returns the current file pointer location (or (off_t)-1)
off_t file_offset(int fd);

/// Tells wether a file exists and is readable
bool file_exists(char const *file_name);

/** Writing onto a file, logging on error and retrying on EINTR.
 * @return 0 on success, -1 on error.
 */
int file_write(int fd, void const *buf, size_t len);

/** Wrapper around writev, logging on error and retrying while there's progress.
 * @return 0 on success, -1 on error.
 */
int file_writev(int fd, struct iovec *iov, int iovcnt);

/** Reading a file, logging on error and retrying on EINTR.
 * @return the number of read bytes on success, -1 on error.
 */
ssize_t file_read(int fd, void *buf, size_t len);

/// Seek into a file, logging on error.
ssize_t file_seek(int fd, off_t offset, int whence);

/// Return the whole content of a file (malloced).
void *file_load(char const *file_name, size_t *len_);

/** Call a function for each line of a file
 * The foreach is stopped as soon as the callback does not return 0.
 * @return the last returned value from the callback.
 */
int file_foreach_line(char const *filename, int (*cb)(char *line, size_t len, va_list), ...);

/** Change to this directory, loging on error.
 * if is_filename then perform a basedir first.
 * @return -1 on error, 0 on success.
 */
int chdir_for_file(char const *dir, bool is_filename);

void files_init(void);
void files_fini(void);

#endif
