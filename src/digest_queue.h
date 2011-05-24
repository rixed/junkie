// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef DIGEST_QUEUE_H_110202
#define DIGEST_QUEUE_H_110202
#include <stdint.h>
#include <junkie/tools/mutex.h>

#define DIGEST_SIZE 16

struct digest_queue *digest_queue_new(unsigned size);
void digest_queue_del(struct digest_queue *);
int digest_queue_resize(struct digest_queue *, unsigned size);

enum digest_status {
    DIGEST_MATCH, DIGEST_NOMATCH, DIGEST_UNKNOWN
};
enum digest_status digest_queue_find(struct digest_queue *, uint8_t buf[DIGEST_SIZE], struct timeval const *frame_tv, unsigned delay_usec);

void digest_frame(uint8_t buf[DIGEST_SIZE], size_t size, uint8_t *restrict packet);

#endif
