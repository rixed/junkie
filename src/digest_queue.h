// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef DIGEST_QUEUE_H_110202
#define DIGEST_QUEUE_H_110202
#include <stdint.h>
#include <stdbool.h>
#include "junkie/tools/timeval.h"

bool digest_queue_find(size_t cap_len, uint8_t *packet, uint8_t dev_id, struct timeval const *frame_tv);

void digest_init(void);
void digest_fini(void);

#endif
