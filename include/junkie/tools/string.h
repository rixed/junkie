#ifndef STRING_140127
#define STRING_140127
#include <junkie/config.h>
#include <junkie/cpp.h>

#ifndef HAVE_STRNSTR
char const *strnstr(char const *haystack, char const *needle, size_t len) pure_;
#endif

// Copy src to dest always NULL terminated.
// Fill at most dest_size bytes including NULL
void copy_string(char *dest, char const *src, size_t dest_size);

#endif
