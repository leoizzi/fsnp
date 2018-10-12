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
#include <stdint.h>
#include <memory.h>
#include <stdlib.h>

#include "peer/keys_cache.h"

#include "struct/hashtable.h"
#include "struct/linklist.h"

#include "fsnp/fsnp.h"

#define CACHE_MAX_SIZE 1UL << 22 // 4.194.304

static hashtable_t *cache = NULL;

struct key_cached {
	sha256_t key;
	linked_list_t *owners;
};

/*
 * Free callback for the cache hashtable
 */
static void ht_free_callback(void *item)
{
	struct key_cached *kc = (struct key_cached *)item;

	list_destroy(kc->owners);
	free(kc);
}

static void list_free_callback(void *item)
{
	struct fsnp_peer *peer = (struct fsnp_peer *)item;

	free(peer);
}

bool init_keys_cache(void)
{
	cache = ht_create(0, CACHE_MAX_SIZE, ht_free_callback);
	if (!cache) {
		return false;
	}

	return true;
}

/*
 * Add a new key_cached to the hashtable.
 * Return 0 on success, -1 otherwise
 */
static int add_new_key(sha256_t key, const struct fsnp_peer *owner)
{
	struct key_cached *kc = NULL;
	struct fsnp_peer *o = NULL;
	int ret = 0;

	kc = malloc(sizeof(struct key_cached));
	if (!kc) {
		return -1;
	}

	kc->owners = list_create();
	if (!kc->owners) {
		free(kc);
		return -1;
	}

	o = malloc(sizeof(struct fsnp_peer));
	if (!o) {
		list_destroy(kc->owners);
		free(kc);
		return -1;
	}

	list_set_free_value_callback(kc->owners, list_free_callback);
	memcpy(kc->key, key, sizeof(sha256_t));
	memcpy(o, owner, sizeof(struct fsnp_peer));
	ret = list_push_value(kc->owners, o);
	if (ret < 0) {
		list_destroy(kc->owners);
		free(kc);
		free(o);
		return -1;
	}

	ret = ht_set(cache, key, sizeof(sha256_t), kc, sizeof(struct key_cached));
	if (ret < 0) {
		list_destroy(kc->owners);
		free(kc);
		free(o);
		return -1;
	}

	return 0;
}

struct duplicate {
	struct fsnp_peer *owner;
	bool d;
};

/*
 * Check that the same peer isn't adding the same key twice
 */
static int avoid_duplicate_callback(void *item, size_t idx, void *user)
{
	struct fsnp_peer *owner = (struct fsnp_peer *)item;
	struct duplicate *duplicate = (struct duplicate *)user;

	UNUSED(idx);

	if (owner->ip == duplicate->owner->ip) {
		if (owner->port == duplicate->owner->port) {
			duplicate->d = true;
			return STOP;
		} else {
			return GO_AHEAD;
		}
	} else {
		return GO_AHEAD;
	}
}

/*
 * Update an existing key_cached in the hashtable by adding to it 'owner'.
 * Return 0 on success, -1 otherwise
 */
static int add_to_key(struct key_cached *kc, struct fsnp_peer *owner)
{
	struct fsnp_peer *o = NULL;
	int ret = 0;
	struct duplicate duplicate;

	duplicate.owner = owner;
	duplicate.d = false;
	list_foreach_value(kc->owners, avoid_duplicate_callback, &duplicate);
	if (duplicate.d) {
		return 0;
	}

	o = malloc(sizeof(struct fsnp_peer));
	if (!o) {
		return -1;
	}

	memcpy(o, owner, sizeof(struct fsnp_peer));
	ret = list_push_value(kc->owners, o);
	if (ret < 0) {
		free(o);
		return -1;
	}

	return 0;
}

int cache_add_keys(uint32_t num_files, uint8_t *keys, struct fsnp_peer *owner)
{
	struct key_cached *kc = NULL;
	uint8_t *sha = NULL;
	uint32_t i = 0;
	int ret = 0;

	for (i = 0; i < num_files; i++) {
		sha = keys + i * sizeof(sha256_t);
		kc = ht_get(cache, sha, sizeof(sha256_t), NULL);
		if (!kc) {
			ret = add_new_key(sha, owner);
		} else {
			ret = add_to_key(kc, owner);
		}

		if (ret < 0) {
			break;
		}
	}

	return ret;
}

/*
 * Go through every fsnp_peer in 'owners'. If one of them matches the one passed
 * to 'cache_rm_keys' remove it from the list
 */
static int cache_list_rm_keys_callback(void *item, size_t idx, void *user)
{
	struct fsnp_peer *owner = (struct fsnp_peer *)user;
	struct fsnp_peer *o = (struct fsnp_peer *)item;

	UNUSED(idx);

	if (owner->ip == o->ip) {
		if (owner->port == o->port) {
			return REMOVE_AND_GO;
		} else {
			return GO_AHEAD;
		}
	} else {
		return GO_AHEAD;
	}
}

/*
 * Go over all the key_cached struct  stored in 'cache' and remove 'user' (which
 * is 'owner' in cache_rm_keys) from the 'owners' list.
 * If after this 'owners' is empty remove the key_cached from the hashtable.
 */
static ht_iterator_status_t cache_ht_rm_keys_callback(hashtable_t *table,
                                                      void *value, size_t vlen,
                                                      void *user)
{
	struct key_cached *kc = (struct key_cached *)value;

	UNUSED(table);
	UNUSED(vlen);

	list_foreach_value(kc->owners, cache_list_rm_keys_callback, user);
	if (list_count(kc->owners) == 0) {
		return HT_ITERATOR_REMOVE;
	} else {
		return HT_ITERATOR_CONTINUE;
	}
}

void cache_rm_keys(struct fsnp_peer *owner)
{
	ht_foreach_value(cache, cache_ht_rm_keys_callback, owner);
}

void close_keys_cache(void)
{
	ht_destroy(cache);
	cache = NULL;
}