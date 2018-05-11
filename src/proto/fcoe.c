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

#include "junkie/tools/miscmacs.h"
#include "junkie/tools/tempstr.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/eth.h"
#include "junkie/proto/fcoe.h"

#undef LOG_CAT
#define LOG_CAT proto_fcoe_log_category

LOG_CATEGORY_DEF(proto_fcoe);

/* Size of header+footer of FCoE (as defined in T11.3) */
#define FCOE_WRAPPER_SIZE 18

static void fcoe_proto_info_ctor(struct fcoe_proto_info *info, struct parser *parser, struct proto_info *parent, size_t packet_len, size_t payload, uint8_t version, uint8_t sof, uint8_t eof)
{
    proto_info_ctor(&info->info, parser, parent, packet_len, payload);
    info->version = version;
    info->sof = sof;
    info->eof = eof;
}

static enum proto_parse_status fcoe_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    /* We expect a packet size such that the data that contains the
     * ethernet type (0x8906) and the payload are a multiple of a
     * "word" (4 bytes). 18 bytes is the minimum size if the
     * encapsulated FC Frame is empty. */
    if (wire_len < FCOE_WRAPPER_SIZE || (wire_len - 2) % 4 != 0) {
        return PROTO_PARSE_ERR;
    }
    /* We need the whole packet */
    if (cap_len < wire_len) {
        return PROTO_TOO_SHORT;
    }

    /* packet[1]..packet[12] are reserved (always 0?) */
    if ((packet[0] & 0x0f) != 0 || packet[1] != 0) {
        // Probably pre T11.3. Not supported.. yet.
        return PROTO_PARSE_ERR;
    }

    int version = (packet[0] & 0xf0) >> 4;

    int sof = packet[13]; // start of frame
    int eof = packet[wire_len - 4]; // end of frame

    switch (sof) {
    case 0x28: // SOFf
    case 0x2d: // SOFi2
    case 0x35: // SOFn2
    case 0x2e: // SOFi3
    case 0x36: // SOFn3
        // Valid SOF
        break;
    default:
        return PROTO_PARSE_ERR;
    }

    switch (eof) {
    case 0x41: // EOFn
    case 0x42: // EOFt
    case 0x49: // EOFni
    case 0x50: // EOFa
        // Valid EOF
        break;
    default:
        return PROTO_PARSE_ERR;
    }

    struct fcoe_proto_info info;
    fcoe_proto_info_ctor(&info, parser, parent, FCOE_WRAPPER_SIZE, wire_len-FCOE_WRAPPER_SIZE, version, sof, eof);
    return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}

static char const *fcoe_info_2_str(struct proto_info const *info_)
{
    struct fcoe_proto_info *info = DOWNCAST(info_, info, fcoe_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, version=%d, sof=0x%02x, eof=0x%02x",
             proto_info_2_str(info_),
             info->version,
             info->sof,
             info->eof);
    return str;
}

static void const *fcoe_info_addr(struct proto_info const *info_, size_t *size)
{
    struct fcoe_proto_info const *info = DOWNCAST(info_, info, fcoe_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

/* Init */

static struct uniq_proto uniq_proto_fcoe;
struct proto *proto_fcoe = &uniq_proto_fcoe.proto;
static struct eth_subproto fcoe_eth_subproto;

void fcoe_init(void)
{
    log_category_proto_fcoe_init();

    static struct proto_ops const ops = {
        .parse       = fcoe_parse,
        .parser_new  = uniq_parser_new,
        .parser_del  = uniq_parser_del,
        .info_2_str  = fcoe_info_2_str,
        .info_addr   = fcoe_info_addr
    };
    uniq_proto_ctor(&uniq_proto_fcoe, &ops, "FCoE", PROTO_CODE_FCOE);
    eth_subproto_ctor(&fcoe_eth_subproto, ETH_PROTO_FCOE, proto_fcoe);
}

void fcoe_fini(void)
{
#   ifdef DELETE_ALL_AT_EXIT
    eth_subproto_dtor(&fcoe_eth_subproto);
    uniq_proto_dtor(&uniq_proto_fcoe);
#   endif
    log_category_proto_fcoe_fini();
}
