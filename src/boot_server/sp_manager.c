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

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <pthread.h>

#include "boot_server/sp_manager.h"
#include "boot_server/server_fsnp.h"

#include "struct/linklist.h"

#define MAX_SP 10

static linked_list_t *sp_list = NULL;
pthread_mutex_t sp_mtx;

static void free_callback(void *val)
{
	struct fsnp_server_sp *node = (struct fsnp_server_sp *)val;
	free(node);
}

int init_sp_manager(void)
{
	int err;

	sp_list = list_create();
	if (!sp_list) {
		return -1;
	}

	list_set_free_value_callback(sp_list, free_callback);
	err = pthread_mutex_init(&sp_mtx, NULL);
	if (err) {
		return -1;
	}

	return 0;
}

void close_sp_manager(void)
{
	list_destroy(sp_list);
}

int add_sp(struct fsnp_server_sp *sp)
{
	return list_push_value(sp_list, sp);
}

struct user_rm_sp_iterator {
	struct fsnp_peer *sp;
	fsnp_peer_type_t type;
	uint64_t pos;
};

static int list_rm_sp_iterator(void *item, size_t idx, void *user)
{
	struct user_rm_sp_iterator *ursi = (struct user_rm_sp_iterator *)user;
	struct fsnp_server_sp *ssp = (struct fsnp_server_sp *)item;

	if (ursi->sp->ip != ssp->addr.s_addr) {
		return GO_AHEAD;
	}

	if (ursi->type == PEER) {
		if (ursi->sp->port == ssp->p_port) {
			ursi->pos = idx;
			return STOP;
		} else {
			return GO_AHEAD;
		}
	} else { // ursi->type == SUPERPEER
		if (ursi->sp->port == ssp->sp_port) {
			ursi->pos = idx;
			return STOP;
		} else {
			return GO_AHEAD;
		}
	}
}

struct fsnp_server_sp *rm_sp(struct fsnp_peer *sp, fsnp_peer_type_t type)
{
	struct user_rm_sp_iterator user;

	user.sp = sp;
	user.type = type;
	list_foreach_value(sp_list, list_rm_sp_iterator, &user);
	return list_fetch_value(sp_list, user.pos);
}

/*
 * Do a copy of the list, so that it's impossible modify the original list
 * accidentally
 */
static int list_copy_iterator(void *item, size_t idx, void *user)
{
	UNUSED(idx);
	linked_list_t *copy_list = (linked_list_t *)user;
	struct fsnp_server_sp *sp = (struct fsnp_server_sp *)item;
	struct fsnp_server_sp *copy = NULL;

	copy = malloc(sizeof(struct fsnp_server_sp));
	if (!copy) {
		return STOP;
	}

	copy->addr = sp->addr;
	copy->p_port = sp->p_port;
	copy->sp_port = sp->sp_port;
	list_push_value(copy_list, copy);
	return GO_AHEAD;
}

linked_list_t *read_all_sp(void)
{
	linked_list_t *list_copy = NULL;
	size_t it_num = 0;

	list_copy = list_create();
	if (!list_copy) {
		return NULL;
	}

	list_set_free_value_callback(list_copy, free_callback);
	it_num = (size_t)list_foreach_value(sp_list, list_copy_iterator, list_copy);
	if (it_num != list_count(sp_list)) { // something went wrong during the copy
		list_destroy(list_copy);
		return NULL;
	}

	return list_copy;
}

struct fsnp_peer *read_sp_by_type(uint8_t *num_sp, fsnp_peer_type_t type)
{
	size_t sp_tot = 0;
	uint32_t i = 0;
	struct fsnp_peer *sp = NULL;
	struct fsnp_server_sp *ssp = NULL;
	int ret = 0;

	sp_tot = list_count(sp_list);
	*num_sp = (uint8_t)(sp_tot > MAX_SP ? MAX_SP : sp_tot);

	sp = malloc(sizeof(struct fsnp_peer) * *num_sp);
	if (!sp) {
		return NULL;
	}

	for (i = 0; i < *num_sp; i++) {
		ssp = list_shift_value(sp_list); // Get the head of the list
		if (!ssp) {
			fprintf(stderr, "WARNING: sp_manager - Unable to get the %u element"
				            " from the list\n", i);
			continue;
		}

		// Fill the struct
		sp[i].ip = ssp->addr.s_addr;
		if (type == PEER) {
			sp[i].port = ssp->p_port;
		} else {
			sp[i].port = ssp->sp_port;
		}

		// push the value back in the tail
		ret = list_push_value(sp_list, ssp);
		if (ret < 0) {
			fprintf(stderr, "WARNING: sp_manager - Unable to push back the %u "
				            "element of the list\n", i);
		}
	}

	return sp;
}

size_t count_sp(void)
{
	return list_count(sp_list);
}

void lock_sp_list(void)
{
	int err = 0;

	err = pthread_mutex_lock(&sp_mtx);
	if (err) {
		fprintf(stderr, "Unable to lock the mutex. In this case it's impossible"
				  " to continue. Aborting\n\n");
		exit(EXIT_FAILURE);
	}
}

void unlock_sp_list(void)
{
	int err = 0;

	err = pthread_mutex_unlock(&sp_mtx);
	if (err) {
		fprintf(stderr, "Unable to unlock the mutex. In this case it's"
				  " impossible to continue. Aborting\n\n");
		exit(EXIT_FAILURE);
	}
}

#undef MAX_SP