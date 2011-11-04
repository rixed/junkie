// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef SERIALIZE_H_111031
#define SERIALIZE_H_111031
#include <stdint.h>
#include "junkie/proto/proto.h"
#include "junkie/tools/timeval.h"
#include "junkie/tools/ip_addr.h"

#define MSG_MAX_SIZE 5000
#define MSG_PROTO_INFO 1
#define MSG_PROTO_STATS 2
#define DATAGRAM_MAX_SIZE 65535

static inline void serialize_1(uint8_t **buf, unsigned v)
{
    **buf = v;
    (*buf)++;
}

static inline void serialize_2(uint8_t **buf, unsigned v)
{
    serialize_1(buf, v);
    serialize_1(buf, v>>8U);
}

static inline void serialize_3(uint8_t **buf, unsigned v)
{
    serialize_2(buf, v);
    serialize_1(buf, v>>16U);
}

static inline void serialize_4(uint8_t **buf, unsigned v)
{
    serialize_2(buf, v);
    serialize_2(buf, v>>16U);
}

static inline void serialize_n(uint8_t **buf, void const *src, size_t n)
{
    memcpy(*buf, src, n);
    (*buf) += n;
}

static inline void serialize_str(uint8_t **buf, char const *s)
{
    unsigned c;
    for (c = 0; s[c] != '\0'; c++) {
        (*buf)[c+2] = s[c];
    }
    (*buf)[0] = c;  // Note: must be same endianness than serialize_2()
    (*buf)[1] = c>>8;
    *buf += c+2;
}

static inline unsigned deserialize_1(uint8_t const **buf)
{
    return *((*buf)++);
}

static inline uint16_t deserialize_2(uint8_t const **buf)
{
    return deserialize_1(buf) + (deserialize_1(buf)<<8U);
}

static inline uint32_t deserialize_3(uint8_t const **buf)
{
    return deserialize_2(buf) + (deserialize_1(buf)<<16U);
}

static inline uint32_t deserialize_4(uint8_t const **buf)
{
    return deserialize_2(buf) + (deserialize_2(buf)<<16U);
}

static inline void deserialize_n(uint8_t const **buf, void *dst, size_t n)
{
    memcpy(dst, *buf, n);
    (*buf) += n;
}

static inline void deserialize_str(uint8_t const **buf, char *dst, size_t max_len)
{
    unsigned n = deserialize_2(buf);
    assert(n < max_len);
    deserialize_n(buf, (uint8_t *)dst, n);
    dst[n] = '\0';
}

void serialize_proto_stack(uint8_t **buf, struct proto_info const *last);
int deserialize_proto_stack(uint8_t const **buf, int (*okfn)(struct proto_info *));

void serialize_init(void);
void serialize_fini(void);

#endif
