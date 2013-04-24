// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef SERIALIZE_H_111031
#define SERIALIZE_H_111031
#include <stdint.h>
#include "junkie/proto/proto.h"
#include "junkie/tools/serialization.h"
#include "junkie/tools/timeval.h"
#include "junkie/tools/ip_addr.h"

#define MSG_MAX_SIZE 5000
#define MSG_PROTO_INFO 1
#define MSG_PROTO_STATS 2
#define SERIALIZER_DEFAULT_SERVICE "28999"

void serialize_proto_stack(uint8_t **buf, struct proto_info const *last, struct timeval const *now);
void deserialize_proto_stack(uint8_t const **buf);

void serialize_init(void);
void serialize_fini(void);

#endif
