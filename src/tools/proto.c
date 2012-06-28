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
#include "junkie/tools/proto.h"
#include "junkie/proto/rtp.h"

char const *rtp_payload_type_2_str(uint8_t type)
{
    static char const *strs[] = {
        "PCMU", "reserved", "reserved", "GSM", "G723", "DVI4/8k", "DVI4/16k", "LPC",
        "PCMA", "G722", "L16/2chan", "L16/mono", "QCELP", "CN", "MPA", "G728",
        "DVI4/11k", "DVI4/22k", "G729", "reserved", "unassigned", "unassigned", "unassigned", "unassigned",
        "unasigned", "CelB", "JPEG", "unassigned", "nv", "unassigned", "unassigned", "H261",
        "MPV", "MP2T", "H263"
    };
    if (type < NB_ELEMS(strs)) return strs[type];
    else if (type >= 35 && type <= 71) return "unasigned";
    else if (type >= 72 && type <= 76) return "reserved";
    else if (type >= 77 && type <= 95) return "unassigned";
    else if (type >= 96 && type <= 127) return "dynamic";
    return "invalid";
}

