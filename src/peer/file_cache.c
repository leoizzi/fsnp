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

#include <stdbool.h>

#include "peer/file_cache.h"

#include "struct/hashtable.h"

#include "fsnp/fsnp.h"

#define CACHE_MAX_SIZE 1UL << 22 // 4.194.304

static hashtable_t *cache = NULL;

struct file_cached {
	sha256_t key;
	linked_list_t *owners;
	unsigned int num_owners;
};

/*
 * Free callback for the cache hashtable
 */
static void cache_free_callback(void *item)
{
	struct file_cached *file = (struct file_cached *)item;

	list_destroy(file->owners);
	free(file);
}

bool init_file_cache(void)
{
	cache = ht_create(0, CACHE_MAX_SIZE, cache_free_callback);
	if (!cache) {
		return false;
	}

	return true;
}

void close_file_cache(void)
{
	ht_destroy(cache);
	cache = NULL;
}