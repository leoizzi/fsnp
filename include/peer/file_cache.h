/*
 *  This file is part of fsnp.
 *
 *  fsnp is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  fsnp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with fsnp. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef FSNP_FILE_CACHE_H
#define FSNP_FILE_CACHE_H

#include <stdbool.h>

#include "fsnp/fsnp.h"

#include "compiler.h"

FSNP_BEGIN_DECL

/*
 * Initialize all the resources for using the file cache
 */
bool init_file_cache(void);

/*
 * Add a set of files to the file cache. The keys are passed as uint8_t instead
 * of sha256_t since this is the format used by the join and update messages
 */
int cache_add_files(int num_files, const uint8_t *keys,
					const struct fsnp_peer *owner);

/*
 * Remove all the files belonging to owner
 */
void cache_rm_files(const struct fsnp_peer *owner);

/*
 * Close the file cache, releasing all the resources allocated
 */
void close_file_cache(void);
FSNP_END_DECL

#endif //FSNP_FILE_CACHE_H
