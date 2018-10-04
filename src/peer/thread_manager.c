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
#include <stdbool.h>

#include "struct/linklist.h"

#include "peer/thread_manager.h"

#ifdef FSNP_MEM_DEBUG
#include "fsnp/sha-256.h"
#endif

struct launch_data {
#ifndef FSNP_MEM_DEBUG
	pthread_t tid;
#else
	sha256_t tid;
#endif
	void *data;
	entry_point e;
	char name[128]; // useful for debugging
};

static linked_list_t *running_threads;
static linked_list_t *closed_threads;

static void free_callback(void *val)
{
	struct launch_data *ld = (struct launch_data *)val;

	if (ld->data) {
		free(ld->data);
	}

	free(ld);
}

int init_thread_manager(void)
{
	running_threads = list_create();
	if (!running_threads) {
		return -1;
	}

	closed_threads = list_create();
	if (!closed_threads) {
		list_destroy(running_threads);
		return -1;
	}

	list_set_free_value_callback(closed_threads, free_callback);
	return 0;
}

/*
 * Iterator callback for searching threads that need to be removed from the
 * list
 */
static int find_n_remove_callback(void *item, size_t idx, void *user)
{
	struct launch_data *ld1 = (struct launch_data *)item;
	struct launch_data *ld2 = (struct launch_data *)user;

	UNUSED(idx);

#ifndef FSNP_MEM_DEBUG
	if (pthread_equal(ld1->tid, ld2->tid)) {
#else
	if (!memcmp(ld1->tid, ld2->tid, sizeof(sha256_t))) {
#endif
		return REMOVE_AND_STOP;
	} else {
		return GO_AHEAD;
	}
}

/*
 * Entry point for all the threads spawned by the thread manager.
 * Manage the thread life cycle inside the two lists
 */
static void *start(void *d)
{
	int ret = 0;
	struct launch_data *ld = (struct launch_data *)d;

	ret = list_push_value(running_threads, ld);
	if (ret < 0) {
		fprintf(stderr, "thread-manager - Unable to add the entry to the running"
				  " list\n");
	}

	ld->e(ld->data);

	list_foreach_value(running_threads, find_n_remove_callback, ld);
	ret = list_push_value(closed_threads, ld);
	if (ret < 0) {
		fprintf(stderr, "thread-manager - Unable to add the entry to the closed"
		                " list\n");
	}
#ifndef FSNP_MEM_DEBUG
	pthread_exit(NULL);
#else
	return NULL;
#endif
}

int start_new_thread(entry_point e, void *data, const char *name)
{

	struct launch_data *ld = NULL;

	ld = malloc(sizeof(struct launch_data));
	if (!ld) {
		return -1;
	}

	ld->data = data;
	ld->e = e;
	if (name) {
		strncpy(ld->name, name, sizeof(ld->name));
	}

#ifndef FSNP_MEM_DEBUG
	if (pthread_create(&ld->tid, NULL, start, ld)) {
		free(ld);
		return -1;
	}

	return 0;
#else
	sha256(&ld->data, sizeof(void *), ld->tid);
	start(ld);
#endif
}

void close_thread_manager(void)
{
	list_set_free_value_callback(running_threads, free_callback);
	list_destroy(running_threads);
	list_destroy(closed_threads);
}

/*
 * Iterator callback for joining threads
 */
static int join_callback(void *item, size_t idx, void *user)
{
	struct launch_data *ld = (struct launch_data *)item;

	UNUSED(idx);
	UNUSED(user);

#ifndef FSNP_MEM_DEBUG
	pthread_join(ld->tid, NULL);
#ifdef FSNP_DEBUG
	printf("Thread %s joined.\n", ld->name);
#endif // FSNP_DEBUG
	free_callback(ld);
#else // !FSNP_MEM_DEBUG
	free_callback(ld);
#endif // FSNP_MEM_DEBUG
	return REMOVE_AND_GO;
}

void join_threads_if_any(void)
{
	list_foreach_value(closed_threads, join_callback, NULL);
#ifndef FSNP_MEM_DEBUG
#ifdef FSNP_DEBUG
	printf("Peer: ");
	fflush(stdout);
#endif // FSNP_DEBUG
#endif // FSNP_MEM_DEBUG
}