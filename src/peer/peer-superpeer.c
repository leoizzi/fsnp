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
#include <poll.h>

#include "fsnp/fsnp.h"

#include "peer/peer-superpeer.h"
#include "peer/stdin.h"
#include "peer/file_manager.h"
#include "peer/peer.h"
#include "peer/thread_manager.h"

// TODO: THE MOST IMPORTANT ONE!!! Use the pipe in the poll for tell to THIS thread to download a fle from a peer or ask who has a file in the network. DO NOT SPAWN ANOTHER THREAD

struct periodic_data {
	pthread_mutex_t mtx;
	bool closing;
	bool is_running;
};

static struct periodic_data pd;

static void stop_update_thread(void)
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
	err = fsnp_send_update(get_peer_sock(), update);
#ifdef FSNP_DEBUG
	if (err != E_NOERR) {
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
	err = fsnp_send_join(sock, join);
	if (err != E_NOERR) {
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
	PRINT_PEER;

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
#else // !FSNP_MEM_DEBUG
	pd.is_running = false;
#endif // FSNP_MEM_DEBUG
	return 0;
}

#define READ_END 0
#define WRITE_END 1

struct peer_tcp_state {
	int pipe_fd[2];
	int sock;
	bool quit_loop;
	bool send_leave_msg;
	unsigned int timeouts;
};

static struct peer_tcp_state tcp_state;

static void read_sock_msg(void)
{
	struct fsnp_msg *msg = NULL;
	fsnp_err_t err;

	msg = fsnp_read_msg_tcp(tcp_state.sock, 0, NULL, &err);
	if (!msg) {
		fsnp_print_err_msg(err);
		if (err == E_PEER_DISCONNECTED) {
			tcp_state.quit_loop = true;
		}

		return;
	}

	switch (msg->msg_type) {
		case FILE_RES:
			break;

		case ALIVE:
			break;

		case ACK:
			break;

		default:
			fprintf(stderr, "Unexpected message type: %d\n", msg->msg_type);
			PRINT_PEER;
	}

	free(msg);
}

/*
 * Handle an event happened in the socket
 */
static void sock_event(short revents)
{
	if (revents & POLLIN || revents & POLLRDBAND || revents & POLLPRI) {
		read_sock_msg();
	} else if (revents & POLLHUP) {
		printf("The superpeer has disconnected itself. Please join another"
		       " one\n");
		PRINT_PEER;
		tcp_state.quit_loop = true;
	} else {
		tcp_state.quit_loop = true;
	}
}

/*
 * Handle an event happened in the pipe (read side)
 */
static void pipe_event(short revents)
{
	// Whatever happened in the pipe just quit the thread
	UNUSED(revents);

	tcp_state.quit_loop = true;
}

#define SOCK 0
#define PIPE 1

/*
 * Initialize the pollfd array for the poll
 */
static void setup_peer_tcp_poll(struct pollfd *fds)
{
	memset(fds, 0, sizeof(struct pollfd) * 2);
	fds[SOCK].fd = tcp_state.sock;
	fds[SOCK].events = POLLIN | POLLPRI;
	fds[PIPE].fd = tcp_state.pipe_fd[READ_END];
	fds[PIPE].events = POLLIN | POLLPRI;
}

#define POLL_ALIVE_TIMEOUT 30000 // ms
/*
 * Entry point for the thread spawned by 'launch_poll_peer_tcp_sock'.
 * Enter a poll loop for respond to a superpeer and check whether the app is
 * closing, so that we can properly shut down the communication and free the
 * resources
 */
static void peer_tcp_thread(void *data)
{
	struct pollfd fds[2];
	int ret = 0;
	struct fsnp_leave leave;
	fsnp_err_t err;

	UNUSED(data);

	setup_peer_tcp_poll(fds);

	while (!tcp_state.quit_loop) {
		ret = poll(fds, 2, POLL_ALIVE_TIMEOUT);
		if (ret > 0) {
			if (fds[PIPE].revents) {
				pipe_event(fds[PIPE].revents);
				fds[PIPE].revents = 0;
			}

			if (fds[SOCK].revents) {
				sock_event(fds[SOCK].revents);
				fds[SOCK].revents = 0;
			}
		} else if (ret == 0) {
			// TODO: send alive msg
		} else {
			perror("poll");
			tcp_state.quit_loop = true;
		}
	}

	if (tcp_state.send_leave_msg) {
		fsnp_init_leave(&leave);
		err = fsnp_send_leave(tcp_state.sock, &leave);
		if (err != E_NOERR < 0) {
			fsnp_print_err_msg(err);
			PRINT_PEER;
		}
	}

	close(tcp_state.sock);
	close(tcp_state.pipe_fd[READ_END]);
	close(tcp_state.pipe_fd[WRITE_END]);

	tcp_state.sock = 0;
	tcp_state.pipe_fd[READ_END] = 0;
	tcp_state.pipe_fd[WRITE_END] = 0;

	stop_update_thread();
}

/*
 * Set up 'tcp_state' and spawn the relative thread
 */
static void launch_poll_peer_tcp_sock(int sock)
{
	int ret = 0;

	ret = pipe(tcp_state.pipe_fd);
	if (ret < 0) {
		perror("pipe");
		close(sock);
		stop_update_thread();
		return;
	}

	tcp_state.sock = sock;
	tcp_state.quit_loop = false;
	tcp_state.send_leave_msg = false;
	ret = start_new_thread(peer_tcp_thread, NULL, "peer_tcp_thread");
	if (ret < 0) {
		close(sock);
		close(tcp_state.pipe_fd[READ_END]);
		close(tcp_state.pipe_fd[WRITE_END]);
		stop_update_thread();
	}
}

int get_peer_sock(void)
{
	int sock = tcp_state.sock;
	return sock;
}

void leave_sp(void)
{
	ssize_t ret = 0;
	int to_write = 1;

	tcp_state.send_leave_msg = true;
	ret = fsnp_write(tcp_state.pipe_fd[WRITE_END], &to_write, sizeof(int));
	if (ret < 0) {
		perror("Unable to close 'peer_tcp_thread'");
	}
}

void join_sp(const struct fsnp_query_res *query_res)
{
	int choice = 0;
	int sock = 0;
	int ret = 0;

	if (is_superpeer()) {
		printf("You're a superpeer, you can't join another superpeer\n");
		PRINT_PEER;
		return;
	}

	if (tcp_state.sock != 0) { // we're already connected to a superpeer
		printf("You're already connected to a superpeer. Leave him before"
		       " trying to join another one\n");
		PRINT_PEER;
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
		close(sock);
		return;
	}

	ret = read_join_res(sock);
	if (ret < 0) {
		close(sock);
		return;
	}

	launch_poll_peer_tcp_sock(sock);
}

#undef POLL_ALIVE_TIMEOUT
#undef READ_END
#undef WRITE_END
#undef SOCK
#undef PIPE