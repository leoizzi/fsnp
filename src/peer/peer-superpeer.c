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

#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <memory.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include "fsnp/fsnp.h"

#include "peer/peer-superpeer.h"
#include "peer/stdin.h"
#include "peer/file_manager.h"
#include "peer/peer.h"
#include "peer/thread_manager.h"

struct periodic_data {
	pthread_mutex_t mtx;
	bool closing;
	bool is_running;
};

static struct periodic_data pd;

void stop_update_thread(void)
{
	/* safe to check without mutex since it was set by the main thread itself
	 * when it has started the update thread, and this function is called only
	 * by the main thread. */
	if (pd.is_running) {
		pthread_mutex_lock(&pd.mtx);
		pd.closing = true;
		pthread_mutex_unlock(&pd.mtx);
		pd.is_running = false;
	}
}

/*
 * Send an update message to the superpeer
 */
static void send_update_msg(void)
{
	struct fsnp_update *update;
	sha256_t *keys = NULL;
	uint32_t num_k = 0;
	ssize_t w = 0;
	int sock = 0;
	fsnp_err_t err;

#ifdef FSNP_DEBUG
	printf("Sending an update message\n");
#endif

	keys = retrieve_all_keys(&num_k);
	if (!keys) {
#ifdef FSNP_DEBUG
		fprintf(stderr, "send_update_msg - Unable to retrieve all the keys!\n");
#endif
		return;
	}

	update = fsnp_create_update(num_k, keys);
	if (!update) {
#ifdef FSNP_DEBUG
		fprintf(stderr, "Unable to create the update msg\n");
#endif
		free(keys);
		return;
	}

	free(keys);
	sock = get_peer_sock();
	w = fsnp_write_msg_tcp(sock, 0, (struct fsnp_msg *)update, &err);
	if (w < 0) {
#ifdef FSNP_DEBUG
		fsnp_print_err_msg(err);
#endif
	}

#ifdef FSNP_DEBUG
	printf("Update message successfully sent");
#endif

	free(update);
}

/*
 * Ask to the file manager if something has changed
 */
static bool check_for_changes(void)
{
	bool changes;

	changes = update_file_manager();
	return changes;
}

#define SEC_TO_SLEEP 20

/*
 * Every SEC_TO_SLEEP check if something between the shared file is changed.
 * If so send an update message to the superpeer
 */
static void periodic_update(void *data)
{
	struct timespec to_sleep;
	struct timespec unslept;
	int ret = 0;
	bool changes;

	UNUSED(data);

	unslept.tv_sec = SEC_TO_SLEEP;
	unslept.tv_nsec = 0;
	while (true) {
		to_sleep.tv_sec = unslept.tv_sec;
		to_sleep.tv_nsec = unslept.tv_nsec;
		unslept.tv_sec = 0;
		unslept.tv_nsec = 0;
		ret = nanosleep(&to_sleep, &unslept);
		if (ret < 0) { // thread woke up earlier
			continue;
		}
		
		ret = pthread_mutex_lock(&pd.mtx);
		if (ret) {
			break;
		}
		
		if (pd.closing) {
			break;
		}

		ret = pthread_mutex_unlock(&pd.mtx);
		if (ret) {
			break;
		}
		
		changes = check_for_changes();
		if (changes) {
			send_update_msg();
		}

		unslept.tv_sec = SEC_TO_SLEEP;
		unslept.tv_nsec = 0;
	}

	pthread_mutex_destroy(&pd.mtx);
}

#undef SEC_TO_SLEEP

/*
 * Show the superpeers to the user and let him choose to who he has to connect
 */
static int show_sp(const struct fsnp_peer *sp_list, uint8_t num_sp)
{
	int i = 0;
	struct in_addr addr;
	unsigned int choice = 0;
	bool retry = false;

	if (num_sp == 1) {
		addr.s_addr = htonl(sp_list[0].ip);
		printf("\nConnecting to superpeer %s:%hu\n", inet_ntoa(addr),
				                                     sp_list[0].port);
		return 0; // Don't even propose the choice to the user
	}

	do {
		printf("\nChoose a superpeer to join by inserting a number in the range"
		       " [1-%hhu]\n\n", num_sp);
		for (i = 0; i < num_sp; i++) {
			addr.s_addr = htonl(sp_list[i].ip);
			printf("Superpeer %d: %s:%hu\n", i + 1, inet_ntoa(addr),
			       sp_list[i].port);
		}

		printf("Choice: (insert 0 to abort): ");
		fflush(stdout);
		block_stdin();
		scanf("%u", &choice);
		release_stdin();
		if (choice == 0) {
			return -1;
		} else if (choice >= num_sp) {
			fprintf(stderr, "choice %u is not valid!\n", choice);
			retry = true;
		} else {
			retry = false;
		}
	} while (retry);

	return choice - 1;
}

/*
 * Create a connection with the chosen superpeer
 */
static int connect_to_sp(const struct fsnp_peer *sp)
{
	struct in_addr a;
	int sock = 0;

	a.s_addr = sp->ip;

#ifdef FSNP_DEBUG
	printf("Sending a connection request to the superpeer\n");
#endif
	sock = fsnp_create_connect_tcp_sock(a, sp->port);
	if (sock < 0) {
		perror("fsnp_create_connect_tcp_sock - connect_to_sp");
		return -1;
	}

	return sock;
}

/*
 * Send to the superpeer the join message
 */
static int send_join_msg(int sock)
{
	struct fsnp_join *join = NULL;
	sha256_t *keys;
	uint32_t num_keys = 0;
	fsnp_err_t err;
	ssize_t ret = 0;

	keys = retrieve_all_keys(&num_keys);
	if (!keys) {
		fprintf(stderr, "Unable to retrieve all the keys!"
				        " Sending the request without sharing files...\n");
	}

	join = fsnp_create_join(num_keys, keys);

	free(keys);

	if (!join) {
		fprintf(stderr, "Unable to create the join message\n");
		return -1;
	}

#ifdef FSNP_DEBUG
	printf("Sending the join message\n");
#endif
	ret = fsnp_write_msg_tcp(sock, 0, (struct fsnp_msg *)join, &err);
	if (ret < 0) {
		fsnp_print_err_msg(err);
		free(join);
		return -1;
	}

	free(join);
	return 0;
}

/*
 * Read the superpeer's answer
 */
static int read_join_res(int sock)
{
	struct fsnp_msg *msg;
	ssize_t r = 0;
	fsnp_err_t err;
	int ret = 0;

#ifdef FSNP_DEBUG
	printf("Wating for the ACK\n");
#endif
	msg = fsnp_read_msg_tcp(sock, 0, &r, &err);
	if (!msg) {
		fsnp_print_err_msg(err);
		return -1;
	}

	if (msg->msg_type != ACK) {
		fprintf(stderr, "The superpeer didn't respond with an ACK\nClosing the"
				        " communications with him\n");
		free(msg);
		return -1;
	}

	free(msg);
	printf("Superpeer join successfully!\n");
	printf("\nPeer: ");
	fflush(stdout);

#ifndef FSNP_MEM_DEBUG
	// launch the periodic update thread
	ret = pthread_mutex_init(&pd.mtx, NULL);
	if (ret) {
		fprintf(stderr, "Unable to initialize the mutex for the periodic update"
		                " thread. It won't be spawned. This means that the"
		                " superpeer will never receive an update message.\n");
		return -1;
	}

	pd.is_running = true;
	start_new_thread(periodic_update, NULL, "periodic_update");
#endif
	return 0;
}

void join_sp(const struct fsnp_query_res *query_res)
{
	int choice = 0;
	int sock = 0;
	int ret = 0;
	int p_sock = 0;

	if (is_superpeer()) {
		printf("You're a superpeer, you can't join another superpeer\n");
		return;
	}

	p_sock = get_peer_sock();
	if (p_sock != 0) { // we're already connected to a superpeer
		printf("You're already connected to a superpeer. Leave him before"
		       " trying to join another one\n");
		return;
	}

	choice = show_sp(query_res->sp_list, query_res->num_sp);
	if (choice < 0) {
		return;
	}

	sock = connect_to_sp(&query_res->sp_list[choice]);
	if (sock < 0) {
		return;
	}

	ret = send_join_msg(sock);
	if (ret < 0) {
		return;
	}

	ret = read_join_res(sock);
	if (ret < 0) {
		return;
	}

	add_peer_sock(sock);
}