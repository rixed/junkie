#ifndef STRING_BUFFER_140301
#define STRING_BUFFER_140301
#include <iconv.h>
#include <stdbool.h>
#include "junkie/cpp.h"

struct string_buffer {
    char   *head;
    size_t size;
    size_t pos;
    bool   truncated;
};

void string_buffer_ctor(struct string_buffer *buffer, char *head, size_t size);
const char *string_buffer_2_str(struct string_buffer *buffer);

/*
 * Convert and append to buffer using the given iconv character descriptor
 * @params src_len Source size in bytes
 */
size_t buffer_append_unicode(struct string_buffer *buffer, iconv_t cd, char const *src, size_t src_len);

/*
 * Append a null terminated string
 * Multi-bytes characters can be truncated if there is not enough space in buffer
 * Use buffer_append_utf8n for intelligent truncate
 */
size_t buffer_append_string(struct string_buffer *buffer, char const *src);

/*
 * Append a null terminated string or most src_len bytes
 */
size_t buffer_append_stringn(struct string_buffer *buffer, char const *src, size_t src_len);
size_t buffer_append_char(struct string_buffer *buffer, char const src);
size_t buffer_append_hexstring(struct string_buffer *buffer, char const *src, size_t src_len);
void buffer_rollback(struct string_buffer *buffer, size_t size);
void buffer_rollback_utf8_char(struct string_buffer *buffer, size_t size);
void buffer_rollback_incomplete_utf8_char(struct string_buffer *buffer);
size_t buffer_append_printf(struct string_buffer *buffer, char const *fmt, ...) a_la_printf_(2, 3);

/* Remove superfluous spaces. Double the quoted char as required by the CSV syntax.
 * *truncated will be set to true if the output was not large enough
 * to hold the resulting escaped string.
 * Src is expected to be utf8
 */
void buffer_append_escape_quotes(struct string_buffer *buffer, char const *src, size_t src_max, char quoted_char, bool normalize);

static inline size_t buffer_left_size(struct string_buffer *buffer)
{
    return buffer->size - buffer->pos;
}

/*
 * Add null terminator to buffer and return it
 */
char *buffer_get_string(struct string_buffer *buffer);

#endif

