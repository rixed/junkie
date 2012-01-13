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
#include <stdlib.h>
#include <stdint.h>
#include "junkie/tools/serialization.h"

extern inline void serialize_1(uint8_t **buf, uint_least8_t v);
extern inline void serialize_2(uint8_t **buf, uint_least16_t v);
extern inline void serialize_3(uint8_t **buf, uint_least32_t v);
extern inline void serialize_4(uint8_t **buf, uint_least32_t v);
extern inline void serialize_8(uint8_t **buf, uint_least64_t v);
extern inline void serialize_n(uint8_t **buf, void const *src, size_t n);
extern inline void serialize_str(uint8_t **buf, char const *s);
extern inline uint_least8_t deserialize_1(uint8_t const **buf);
extern inline uint_least16_t deserialize_2(uint8_t const **buf);
extern inline uint_least32_t deserialize_3(uint8_t const **buf);
extern inline uint_least32_t deserialize_4(uint8_t const **buf);
extern inline uint_least64_t deserialize_8(uint8_t const **buf);
extern inline void deserialize_n(uint8_t const **buf, void *dst, size_t n);
extern inline void deserialize_str(uint8_t const **buf, char *dst, size_t max_len);

