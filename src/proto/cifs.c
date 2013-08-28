// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2010, SecurActive.
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

#include "junkie/proto/cifs.h"

#undef LOG_CAT
#define LOG_CAT proto_cifs_log_category

LOG_CATEGORY_DEF(proto_cifs);

#define CIFS_HEADER_SIZE sizeof(struct cifs_hdr)

struct cifs_hdr {
    uint32_t code;
    uint8_t  command;
    uint32_t status;

    // flags
    unsigned request:1;
    unsigned notify:1;
    unsigned oplocks:1;
    unsigned canonicalized:1;
    unsigned case_sensitivity:1;
    unsigned receive_buffer_posted:1;
    unsigned lock_and_read:1;

    // flags 2

    unsigned unicode:1;
    unsigned error_code_type:1;
    unsigned execute_only_reads:1;
    unsigned dfs:1;
    unsigned reparse_path:1;
    unsigned long_names:1;
    unsigned security_signatures_required:1;
    unsigned compressed:1;
    unsigned extended_attributes:1;
    unsigned long_names_allowed:1;

    uint16_t process_id_high;
    uint64_t signature;
    uint16_t reserved;
    uint16_t tree_id;
    uint16_t process_id;
    uint16_t user_id;
    uint16_t multiplex_id;
} packed_;


static void const *cifs_info_addr(struct proto_info const *info_, size_t *size)
{
    struct cifs_proto_info const *info = DOWNCAST(info_, info, cifs_proto_info);
    if (size) *size = sizeof(*info);
    return info;
}

static char const *cifs_info_2_str(struct proto_info const *info_)
{
    struct cifs_proto_info const *info = DOWNCAST(info_, info, cifs_proto_info);
    char *str = tempstr_printf("%s, command=%#04x, status=0x%08"PRIx32,
            proto_info_2_str(info_),
            info->command,
            info->status);
    return str;
}

static int packet_is_cifs(struct cifs_hdr const *cifshdr)
{
    return READ_U32N(&cifshdr->code) == 0xff534d42; // 0xff + SMB
}

static void cifs_proto_info_ctor(struct cifs_proto_info *info, struct parser *parser, struct proto_info *parent, size_t header, size_t payload, struct cifs_hdr const * cifshdr)
{
    proto_info_ctor(&info->info, parser, parent, header, payload);
    info->command = READ_U8(&cifshdr->command);
    info->status = READ_U32(&cifshdr->status);
}

static enum proto_parse_status cifs_parse(struct parser *parser, struct proto_info *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, size_t tot_cap_len, uint8_t const *tot_packet)
{
    /* Sanity checks */
    if (wire_len < CIFS_HEADER_SIZE) return PROTO_PARSE_ERR;
    if (cap_len <  CIFS_HEADER_SIZE) return PROTO_TOO_SHORT;

    struct cifs_hdr const *cifshdr = (struct cifs_hdr const *) packet;
    if (! packet_is_cifs(cifshdr)) return PROTO_PARSE_ERR;

    struct cifs_proto_info info;
    cifs_proto_info_ctor(&info, parser, parent, CIFS_HEADER_SIZE, wire_len - CIFS_HEADER_SIZE, cifshdr);
    return proto_parse(NULL, &info.info, way, NULL, 0, 0, now, tot_cap_len, tot_packet);
}

static struct uniq_proto uniq_proto_cifs;
struct proto *proto_cifs = &uniq_proto_cifs.proto;

/*
 * Initialization
 */

void cifs_init(void)
{
    log_category_proto_cifs_init();

    static struct proto_ops const ops = {
        .parse      = cifs_parse,
        .parser_new  = uniq_parser_new,
        .parser_del = uniq_parser_del,
        .info_2_str = cifs_info_2_str,
        .info_addr  = cifs_info_addr,
    };
    uniq_proto_ctor(&uniq_proto_cifs, &ops, "CIFS", PROTO_CODE_CIFS);
}

void cifs_fini(void)
{
    uniq_proto_dtor(&uniq_proto_cifs);
    log_category_proto_cifs_fini();
}
