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
#include <errno.h>
#include <arpa/inet.h>

#include "peer/keys_cache.h"
#include "peer/file_manager.h"

#include "struct/hashtable.h"
#include "struct/linklist.h"

#include "fsnp/fsnp.h"

#include "slog/slog.h"

#define CACHE_MAX_SIZE 1UL << 22 // 4.194.304

#define STRINGIFY_HASH(key_str, key, i) \
	for (i = 0; i < SHA256_BYTES; i++) { \
		snprintf(&key_str[i], sizeof(uint8_t) + 1, "%hhx", key[i]); \
	}

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

/*
 * Free callback fot the 'owners' field of a key_cached struct
 */
static void list_free_callback(void *item)
{
	struct fsnp_peer *peer = (struct fsnp_peer *)item;

	free(peer);
}

bool init_keys_cache(void)
{
	slog_debug(FILE_LEVEL, "Creating the keys_cache hashtable")
	cache = ht_create(0, CACHE_MAX_SIZE, ht_free_callback);
	if (!cache) {
		slog_error(FILE_LEVEL, "Unable to create the keys_cache hashtable");
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
	char sha_str[SHA256_BYTES];
	unsigned i = 0;
	struct in_addr addr;

	kc = malloc(sizeof(struct key_cached));
	if (!kc) {
		slog_error(FILE_LEVEL, "malloc error %d", errno);
		return -1;
	}

	kc->owners = list_create();
	if (!kc->owners) {
		slog_error(FILE_LEVEL, "list_create");
		free(kc);
		return -1;
	}

	o = malloc(sizeof(struct fsnp_peer));
	if (!o) {
		slog_error(FILE_LEVEL, "malloc error %d", errno);
		list_destroy(kc->owners);
		free(kc);
		return -1;
	}

	STRINGIFY_HASH(sha_str, key, i);
	addr.s_addr = htonl(owner->ip);
	slog_info(FILE_LEVEL, "Added key %s, owner %s:%hu", sha_str,
			inet_ntoa(addr), owner->port);
	list_set_free_value_callback(kc->owners, list_free_callback);
	memcpy(kc->key, key, sizeof(sha256_t));
	memcpy(o, owner, sizeof(struct fsnp_peer));
	ret = list_push_value(kc->owners, o);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Unable to push new entry in key->owners");
		list_destroy(kc->owners);
		free(kc);
		free(o);
		return -1;
	}

	ret = ht_set(cache, key, sizeof(sha256_t), kc, sizeof(struct key_cached));
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Unable to set new entry in cache hashtable");
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
	char sha_str[SHA256_BYTES];
	unsigned i = 0;
	struct in_addr addr;

	duplicate.owner = owner;
	duplicate.d = false;
	addr.s_addr = htonl(owner->ip);
	STRINGIFY_HASH(sha_str, kc->key, i);
	list_foreach_value(kc->owners, avoid_duplicate_callback, &duplicate);
	if (duplicate.d) {
		slog_warn(FILE_LEVEL, "%s:%hu tried to add %s twice", inet_ntoa(addr),
				owner->port, sha_str);
		return 0;
	}

	o = malloc(sizeof(struct fsnp_peer));
	if (!o) {
		slog_error(FILE_LEVEL, "malloc error %d", errno);
		return -1;
	}


	memcpy(o, owner, sizeof(struct fsnp_peer));
	slog_info(FILE_LEVEL, "Adding to %s's owners %s:%hu", inet_ntoa(addr),
			owner->port);
	ret = list_push_value(kc->owners, o);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "kc->owners list_push_value");
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
			slog_info(FILE_LEVEL, "Item found");
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
	char key_str[SHA256_BYTES];
	unsigned i = 0;

	UNUSED(table);
	UNUSED(vlen);

	STRINGIFY_HASH(key_str, kc->key, i);
	slog_debug(FILE_LEVEL, "Removing item %s", key_str);
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
	slog_debug(FILE_LEVEL, "Destroying cache hashtable");
	ht_destroy(cache);
	cache = NULL;
}

#undef STRINGIFY_HASH
#undef CACHE_MAX_SIZE