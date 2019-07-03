// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef FUZZING_H
#define FUZZING_H

/** Fuzz the current packet by mutating some of its bits.
  * Try to target the packet header using some simple/dumb probability.
  * The nearer those bits are from the beginning of the packet, the more chance
  * they get to be mutated.
*/
void fuzz(struct parser *parser, uint8_t const *packet, size_t packet_len, unsigned max_num_fuzzed_bits);

void fuzzing_init(void);
void fuzzing_fini(void);

#endif
