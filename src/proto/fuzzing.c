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
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <limits.h>
#include <math.h>
#include "junkie/tools/log.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/cap.h"
#include "proto/fuzzing.h"


#undef LOG_CAT
#define LOG_CAT proto_log_category

static void do_fuzz(uint8_t const *packet, size_t packet_len, unsigned bits_2_fuzz);
static int nb_bits_to_fuzz(unsigned upper_bound);
static void update_fuzzing_stat(struct proto * protocol);

/// fuzzing statistics
static struct fuzzed_stat {
    unsigned nb_fuzzed_pkt;         /// overall sum of fuzzing operation (an operation may perform several bit mutation) performed on packets
    unsigned nb_fuzzed_proto;       /// number of protocol fuzzed
    unsigned max_fuzzed_pkt_proto;  /// the maximal number of fuzzing operation performed on a protocol
} f_stat;

void fuzz(struct parser *parser, uint8_t const *packet, size_t packet_len, unsigned max_nb_fuzzed_bits)
{
    // Handle the case of the `cap' parser which must not be fuzzed.
    // It is a "fake" parser with a "fake" packet containing unrelevant information in our case.
    if (parser->proto == proto_cap) return;
    // By fuzzing only once out of 3, we have more chance to reach deeper protocols.
    if (rand() % 3) return;

    update_fuzzing_stat(parser->proto);

    if (packet_len != 0) {
        do_fuzz(packet, packet_len, nb_bits_to_fuzz(max_nb_fuzzed_bits));
    }
}

// Return the number of bits to fuzz for a protocolar layer fuzzing action
static int nb_bits_to_fuzz(unsigned upper_bound)
{
    return rand() % (upper_bound + 1);
}

// Increments the protocol counter and update the fuzzing stats
static void update_fuzzing_stat(struct proto * protocol)
{
    if (protocol->fuzzed_times == 0) {
        f_stat.nb_fuzzed_proto ++;
    }

    // incremeting the protocol internal counter : this protocol is just about to get fuzzed!
    protocol->fuzzed_times++;

    // and then updating the fuzzing statistics
    f_stat.nb_fuzzed_pkt++;
    if (protocol->fuzzed_times > f_stat.max_fuzzed_pkt_proto)
        f_stat.max_fuzzed_pkt_proto = protocol->fuzzed_times;
}

// Return a location for the byte
static unsigned get_bit_location(unsigned bits_len)
{
    assert(bits_len > 0);
    double x = drand48();

    // Explanation:
    // This function, f, is the negative function of the gaussian, g, : exp(-(x^2)). So that, f(g(x)) = x
    // f is defined on ]0;1] (used by random function) and 0 <= f(x) < bits_len (valid bit location).
    // The purpose of this function is to return a valid bit location given that the smaller the bit location (y), the larger the chance (x) to get it.
    // Plot this function and checkout that the slope is decreasing as x reach 1: larger bits_len are allowed x is close to 1 to smaller bit location.

    // `coeff' is to fit the function so that each bit in the bits_len is theorically reachable but furthest one have really few chances to.
    // It was set experimentally in order to have a good chance to hit the first quarter of the bits_len.
    double const coeff = 10.;
    unsigned bit_location = sqrt(-log(x) * coeff * bits_len);

    SLOG(LOG_DEBUG, "\tBit location computed: f(%g) = %d", x, bit_location);
    return MIN(bit_location, bits_len - 1);
}

static void mutate_bit(uint8_t *packet, int location) {
    int bit = location % 8;
    int byte = location / 8;
    packet[byte] ^= (1 << (7 - bit));
}

// Actually perform the fuzzing
static void do_fuzz(uint8_t const *packet, size_t packet_len, unsigned bits_2_fuzz)
{
    SLOG(LOG_DEBUG, "Nb bits to fuzz: %u", bits_2_fuzz);
    unsigned const bits_len = packet_len * 8;

    while (bits_2_fuzz-- > 0) {
        unsigned l = get_bit_location(bits_len);
        assert(l < bits_len);
        mutate_bit((uint8_t *)packet, l);
    }
}


void fuzzing_init(void)
{
    // change the seed for the rand function
    srand(time(NULL));
    srand48(time(NULL));
}

void fuzzing_fini(void)
{
    if (0 == f_stat.nb_fuzzed_pkt) return;

    // displays statistic about all protocols
    printf("Fuzzing stats:\n");
    printf("\tAverage fuzzing events by protocols: %g\n", (((double) f_stat.nb_fuzzed_pkt)/f_stat.nb_fuzzed_proto));
    printf("\tNumber of fuzzing events: %u\n", f_stat.nb_fuzzed_pkt);
    printf("\tNumber of protocols fuzzed: %u\n", f_stat.nb_fuzzed_proto);
    printf("\tMaximal number of fuzzing event for a protocol: %u\n", f_stat.max_fuzzed_pkt_proto);
}
