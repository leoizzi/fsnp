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
#include <time.h>
#include <stdbool.h>

#include "peer/request.h"
#include "peer/peer.h"
#include "peer/superpeer.h"
#include "peer/timespec.h"

#include "fsnp/fsnp.h"

#include "struct/hashtable.h"

#include "slog/slog.h"

struct request *create_request(const sha256_t file_hash, bool sent_by_me,
               const struct fsnp_peer *requester)
{
	struct request *req = NULL;

	req = malloc(sizeof(struct request));
	if (!req) {
		return NULL;
	}

	update_timespec(&req->creation_time);
	req->sent_by_me = sent_by_me;
	req->answered = false;
	memcpy(req->file_hash, file_hash, sizeof(sha256_t));
	if (!requester) {
		memset(&req->requester, 0, sizeof(struct fsnp_peer));
	} else {
		memcpy(&req->requester, requester, sizeof(struct fsnp_peer));
	}

	return req;
}

struct invalidate_req_data {
	hashtable_t *ht;
	struct timespec curr;
};

#define INVALIDATE_REQ_THRESHOLD 60.0f // 1 minutes

/*
 * Iterate over all the keys, removing that ones that are expired
 */
static int invalidate_requests_iterator(void *item, size_t idx, void *user)
{
	hashtable_key_t *key = (hashtable_key_t *)item;
	struct invalidate_req_data *data = (struct invalidate_req_data *)user;
	struct request *req = NULL;
	double delta = 0;
	char key_str[SHA256_STR_BYTES];
	uint8_t *p = NULL;
	struct fsnp_whohas whohas;
	struct fsnp_peer self;

	UNUSED(idx);

	req = ht_get(data->ht, key->data, key->len, NULL);
	if (!req) {
		slog_warn(FILE_LEVEL, "Request iterator key not present in the hashtable");
		return GO_AHEAD;
	}

	delta = calculate_timespec_delta(&req->creation_time, &data->curr);
	if (delta > INVALIDATE_REQ_THRESHOLD) {
		p = key->data;
		if (req->sent_by_me) {
			// Tell to the peer that nothing was found
			if (!req->answered) {
				self.ip = get_peer_ip();
				self.port = get_udp_sp_port();
				fsnp_init_whohas(&whohas, &self, p, req->file_hash, 0, NULL);
				communicate_whohas_result_to_peer(&whohas, &req->requester);
			}
		}

		stringify_hash(key_str, p);
		slog_info(FILE_LEVEL, "Invalidating request %s", key_str);
		ht_delete(data->ht, key->data, key->len, NULL, NULL);
	}

	return GO_AHEAD;
}

#undef INVALIDATE_REQ_THRESHOLD

void invalidate_requests(hashtable_t *ht)
{
	linked_list_t *l = NULL;
	struct invalidate_req_data data;

	if (count_requests(ht) == 0) {
		return;
	}

	l = ht_get_all_keys(ht);
	if (!l) {
		slog_error(FILE_LEVEL, "Unable to get all the reqs keys");
		return;
	}

	update_timespec(&data.curr);
	data.ht = ht;
	list_foreach_value(l, invalidate_requests_iterator, &data);
	list_destroy(l);
}

add_req_status_t add_request_to_table(sha256_t key, struct request *req,
		hashtable_t *ht)
{
	int ret = 0;

	ret = ht_set_if_not_exists(ht, key, sizeof(sha256_t), req,
			sizeof(struct request));
	if (ret == 1) {
		return ALREADY_ADDED;
	} else if (ret == 0) {
		return ADDED;
	} else {
		return NOT_ADDED;
	}
}

struct request *get_request(sha256_t key, hashtable_t *ht)
{
	return ht_get(ht, key, sizeof(sha256_t), NULL);
}

void update_request(hashtable_t *ht, sha256_t key, const struct fsnp_whohas *whohas)
{
	struct request *req = NULL;

	req = get_request(key, ht);
	if (!req) {
		return;
	}

	req->answered = true;
	memcpy(&req->whohas, whohas, sizeof(struct fsnp_whohas));
}

void rm_request_from_table(sha256_t key, hashtable_t *ht)
{
	ht_delete(ht, key, sizeof(sha256_t), NULL, NULL);
}

size_t count_requests(hashtable_t *ht)
{
	return ht_count(ht);
}

void reqs_free_callback(void *data)
{
	struct request *r = (struct request *)data;
	free(r);
}