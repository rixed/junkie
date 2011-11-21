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

static char const Id[] = "$Id: dc743f7b4589d91ff5d4b2500ede0f478ebdb2de $";

#undef LOG_CAT
#define LOG_CAT proto_cifs_log_category

LOG_CATEGORY_DEF(proto_cifs);

static int unused_ cifs_parse(struct parser unused_ *parser,
                              unsigned unused_ way,
                              uint8_t const unused_ *packet,
                              size_t unused_ packet_len)
{
    return 0;
}

static struct proto todo_proto_cifs;
struct proto *proto_cifs = &todo_proto_cifs;

/*
 * Initialization
 */

void cifs_init(void)
{
    log_category_proto_cifs_init();
}

void cifs_fini(void)
{
    log_category_proto_cifs_fini();
}
