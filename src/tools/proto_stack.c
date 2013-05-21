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
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "junkie/cpp.h"
#include "junkie/proto/proto.h"
#include "junkie/proto/discovery.h"
#include "junkie/tools/miscmacs.h"
#include "junkie/tools/tempstr.h"
#include "junkie/tools/proto_stack.h"

static char const *proto_name(struct proto_info const *info)
{
    if (info->parser->proto->code == PROTO_CODE_DISCOVERY) {
        struct discovery_proto_info const *pipi = DOWNCAST(info, info, discovery_proto_info);
        return pipi->protocol.name;
    }

    return info->parser->proto->name;
}

static bool update_if_deeper(struct proto_stack *stack, int *len, unsigned depth, struct proto_info const *last)
{
    if (! last) {
        if (depth > stack->depth) {
            stack->depth = depth;
            return true;
        } else {
            return false;
        }
    }

    if (! update_if_deeper(stack, len, depth+1, last->parent)) return false;

    if (*len < (int)sizeof(stack->name) && last->parent /* Skip 'Capture' */) {
        *len += snprintf(stack->name + *len, sizeof(stack->name) - *len, "%s%s", *len > 0 ? "/":"", proto_name(last));
    }
    return true;
}

int proto_stack_update(struct proto_stack *stack, struct proto_info const *last)
{
    int len = 0;
    return update_if_deeper(stack, &len, 0, last) ? 1:0;
}

