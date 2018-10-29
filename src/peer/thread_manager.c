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
#include <errno.h>
#include <unistd.h>

#include "struct/linklist.h"

#include "peer/thread_manager.h"

#include "slog/slog.h"

#ifdef FSNP_DEBUG
#include "peer/peer.h" // for PRINT_PEER
#endif

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
	slog_debug(FILE_LEVEL, "Creating running_threads list");
	running_threads = list_create();
	if (!running_threads) {
		slog_error(FILE_LEVEL, "Unable to create running_theads list");
		return -1;
	}

	slog_debug(FILE_LEVEL, "Creating closed_threads list");
	closed_threads = list_create();
	if (!closed_threads) {
		slog_error(FILE_LEVEL, "Unable to create closed_theads list");
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

	slog_info(FILE_LEVEL, "Thread %s is running", ld->name);
	slog_debug(FILE_LEVEL, "Pushing %s inside running_threads", ld->name);
	ret = list_push_value(running_threads, ld);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Unable to add %s to running_threads", ld->name);
	}

	ld->e(ld->data);

	slog_debug(FILE_LEVEL, "Removing %s from the running_threads list", ld->name);
	list_foreach_value(running_threads, find_n_remove_callback, ld);
	slog_debug(FILE_LEVEL, "Pushing %s inside closed_threads", ld->name);
	ret = list_push_value(closed_threads, ld);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Unable to add %s to closed_threads", ld->name);
	}

	slog_info(FILE_LEVEL, "Thread %s is exiting", ld->name);
#ifndef FSNP_MEM_DEBUG
	pthread_exit(NULL);
#else
	return NULL;
#endif
}

int start_new_thread(entry_point e, void *data, const char *name)
{

	struct launch_data *ld = NULL;
	int ret = 0;

	ld = malloc(sizeof(struct launch_data));
	if (!ld) {
		slog_error(FILE_LEVEL, "malloc error: %d", errno);
		return -1;
	}

	ld->data = data;
	ld->e = e;
	strncpy(ld->name, name, sizeof(ld->name));

#ifndef FSNP_MEM_DEBUG
	ret = pthread_create(&ld->tid, NULL, start, ld);
	if (ret) {
		slog_error(FILE_LEVEL, "pthread_create error: %d", ret);
		free(ld);
		return -1;
	}

	return 0;
#else
	slog_debug(FILE_LEVEL, "FSNP_MEM_DEBUG defined: just calling start");
	sha256(&ld->data, sizeof(void *), ld->tid);
	start(ld);
#endif
}

void close_thread_manager(void)
{
	list_set_free_value_callback(running_threads, free_callback);
	sleep(2); // give the threads enough time to finish their work
	join_threads_if_any();
	slog_debug(FILE_LEVEL, "Destroying running_threads");
	slog_debug(FILE_LEVEL, "In running threads there are still %u threads", list_count(running_threads));
	list_destroy(running_threads);
	slog_debug(FILE_LEVEL, "Destroying closed_threads");
	slog_debug(FILE_LEVEL, "In closed threads there are still %u threads", list_count(closed_threads));
	list_destroy(closed_threads);
}

/*
 * Iterator callback for joining threads
 */
static int join_callback(void *item, size_t idx, void *user)
{
	struct launch_data *ld = (struct launch_data *)item;
	int ret = 0;

	UNUSED(idx);
	UNUSED(user);

#ifndef FSNP_MEM_DEBUG
	ret = pthread_join(ld->tid, NULL);
	if (ret) {
		slog_error(FILE_LEVEL, "pthread_join error %d for thread %s", errno, ld->name);
	} else {
		slog_info(FILE_LEVEL, "Thread %s joined", ld->name);
	}

	free_callback(ld);
#else // !FSNP_MEM_DEBUG
	slog_debug(FILE_LEVEL, "FSNP_MEM_DEBUG defined: just freeing the memory");
	free_callback(ld);
#endif // FSNP_MEM_DEBUG
	return REMOVE_AND_GO;
}

void join_threads_if_any(void)
{
	list_foreach_value(closed_threads, join_callback, NULL);
}