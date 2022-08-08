/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Copyright (c) 2022, GSI Helmholtz Centre for Heavy Ion Research
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <zlib.h>
#include "common.h"

int crc32file(const char *filename, uint32_t *crc32result);
void login_init(struct login_t *login, const char *servername,
                const char *node, const char *password,
                const char *owner, const char *platform,
                const char *fsname, const char *fstype);


#endif /* UTIL_H */
