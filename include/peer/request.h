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

#ifndef FSNP_REQUEST_H
#define FSNP_REQUEST_H

#include <time.h>
#include <stdbool.h>

#include "fsnp/fsnp_types.h"
#include "fsnp/sha-256.h"

#include "struct/hashtable.h"

struct request {
	struct timespec creation_time;
	sha256_t file_hash;
	bool sent_by_me;
	struct fsnp_peer requester; // this field has a mean only if sent_by_me is true
};


void reqs_free_callback(void *data);

/*
 * Create a file request
 */
struct request *create_request(const sha256_t file_hash, bool sent_by_me,
		const struct fsnp_peer *requester);

enum add_req_status {
	ADDED = 0,
	ALREADY_ADDED = 1,
	NOT_ADDED = -1
};
typedef enum add_req_status add_req_status_t;
/*
 * Add req to ht
 */
int add_request_to_table(sha256_t key, struct request *req, hashtable_t *ht);

/*
 * Get a request from hashtable
 */
struct request *get_request(sha256_t key, hashtable_t *ht);

/*
 * Remove req
 */
void rm_request_from_table(sha256_t key, hashtable_t *ht);

/*
 * return the number of requests present in the hashtable
 */
size_t count_requests(hashtable_t *ht);

/*
 * Invalidate any request that has expired
 */
void invalidate_requests(hashtable_t *ht);

#endif //FSNP_REQUEST_H
