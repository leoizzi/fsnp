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
#include <errno.h>
#include <sys/time.h>

#include "fsnp/fsnp.h"

#include "peer/peer-superpeer.h"
#include "peer/stdin.h"
#include "peer/file_manager.h"
#include "peer/peer.h"
#include "peer/thread_manager.h"
#include "peer/superpeer.h"
#include "peer/pipe_macro.h"

#include "slog/slog.h"

struct periodic_data {
	pthread_mutex_t mtx;
	pthread_cond_t cond;
	bool closing;
	bool is_running;
};

static struct periodic_data pd;

static void stop_peer_update_thread(void)
{
	slog_info(FILE_LEVEL, "Stopping the peer-periodic-update thread");
	/* 'is_running' is safe to check without acquiring the mutex since it was
	 * set by the main thread itself when it has started the update thread, and
	 * this function is called only by the main thread. */
	if (pd.is_running) {
		pthread_mutex_lock(&pd.mtx);
		pd.closing = true;
		pthread_cond_signal(&pd.cond);
		pthread_mutex_unlock(&pd.mtx);
		slog_info(FILE_LEVEL, "Update thread has been notified to stop");
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

	slog_debug(FILE_LEVEL, "Sending an update message");

	keys = retrieve_all_keys(&num_k);
	if (!keys) {
		slog_error(FILE_LEVEL, "Unable to retrieve all keys");
		return;
	}

	update = fsnp_create_update(num_k, keys);
	if (!update) {
		slog_error(FILE_LEVEL, "Unable to create the update msg");
		free(keys);
		return;
	}

	free(keys);
	sock = get_peer_sock();
	slog_info(FILE_LEVEL, "Sending update msg");
	err = fsnp_send_update(sock, update);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
	}

	free(update);
}

#define SEC_TO_SLEEP 30

/*
 * Every SEC_TO_SLEEP check if something between the shared file is changed.
 * If so send an update message to the superpeer
 */
static void periodic_update(void *data)
{
	struct timespec to_sleep;
	struct timeval tod;
	int ret = 0;
	bool changes;

	UNUSED(data);

	to_sleep.tv_sec = SEC_TO_SLEEP;
	to_sleep.tv_nsec = 0;
	while (true) {
		gettimeofday(&tod, NULL);
		to_sleep.tv_sec = SEC_TO_SLEEP + tod.tv_sec;
		ret = pthread_mutex_lock(&pd.mtx);
		if (ret) {
			slog_error(FILE_LEVEL, "pthread_mutex_lock error %d", ret);
		}

		slog_debug(FILE_LEVEL, "peer-periodic-update thread is going to sleep");
		ret = pthread_cond_timedwait(&pd.cond, &pd.mtx, &to_sleep);
		if (ret != 0 && ret != ETIMEDOUT) {
			slog_fatal(FILE_LEVEL, "pthread_cond_timedwait returned EINVAL");
			break;
		}

		if (ret == ETIMEDOUT) {
			slog_debug(FILE_LEVEL, "peer-periodic-update has timed out");
		}
		
		if (pd.closing) {
			ret = pthread_mutex_unlock(&pd.mtx);
			if (ret) {
				slog_error(FILE_LEVEL, "pthread_mutex_unlock error %d", ret);
			}

			break;
		}

		ret = pthread_mutex_unlock(&pd.mtx);
		if (ret) {
			slog_error(FILE_LEVEL, "pthread_mutex_unlock error %d", errno);
			break;
		}
		
		changes = check_for_updates();
		if (changes) {
			send_update_msg();
		}
	}

	slog_info(FILE_LEVEL, "Update thread is about to exit");
	pthread_mutex_destroy(&pd.mtx);
	pthread_cond_destroy(&pd.cond);
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
		slog_info(STDOUT_LEVEL, "Connecting to superpeer %s:%hu",
				inet_ntoa(addr), sp_list[0].port);
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
			slog_info(FILE_LEVEL, "User chose to not connect");
			return -1;
		} else if (choice >= num_sp) {
			slog_warn(STDOUT_LEVEL, "choice %u is not valid", choice);
			retry = true;
		} else {
			retry = false;
		}
	} while (retry);

	PRINT_PEER;
	return choice - 1;
}

/*
 * Create a connection with the chosen superpeer
 */
static int connect_to_sp(const struct fsnp_peer *sp)
{
	struct in_addr a;
	int sock = 0;

	a.s_addr = htonl(sp->ip);
	slog_info(FILE_LEVEL, "Sending a connection request to the superpeer %s:%hu",
			inet_ntoa(a), sp->port);
	a.s_addr = sp->ip; // restore to the format expected by fsnp

	sock = fsnp_create_connect_tcp_sock(a, sp->port);
	if (sock < 0) {
		slog_error(FILE_LEVEL, "fsnp_create_connect_to_tcp_sock error %d", errno);
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
		slog_warn(FILE_LEVEL, "Unable to retrieve all the keys. Sending the"
						 " request without sharing files");
	}

	join = fsnp_create_join(num_keys, get_dw_port(), keys);
	free(keys);

	if (!join) {
		slog_error(FILE_LEVEL, "Unable to create the join message. Error %d", errno);
		return -1;
	}

	slog_debug(FILE_LEVEL, "Sending the join message");
	err = fsnp_send_join(sock, join);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
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

	slog_debug(FILE_LEVEL, "Waiting for the ACK");
	msg = fsnp_read_msg_tcp(sock, 0, &r, &err);
	if (!msg) {
		fsnp_log_err_msg(err, false);
		return -1;
	}

	if (msg->msg_type != ACK) {
		slog_debug(FILE_LEVEL, "The superpeer didn't respond with an ACK (%d)"
						 " but with %u. Closing the communications with him",
						 ACK, msg->msg_type);
		free(msg);
		return -1;
	}

	free(msg);
	slog_info(STDOUT_LEVEL, "Superpeer joined successfully.");
	PRINT_PEER;

#ifndef FSNP_MEM_DEBUG
	// launch the periodic update thread
	ret = pthread_mutex_init(&pd.mtx, NULL);
	if (ret) {
		slog_error(FILE_LEVEL, "Unable to initialize the mutex for the"
						       " peer-periodic-update. It won't be spawned. The"
			                   " superpeer will never receive an update message.");
		return -1;
	}

	ret = pthread_cond_init(&pd.cond, NULL);
	if (ret) {
		slog_error(FILE_LEVEL, "Unable to initialize the condition for the"
		                       " peer-periodic-update. It won't be spawned. The"
		                       " superpeer will never receive an update message.");
		pthread_mutex_destroy(&pd.mtx);
	}

	pd.is_running = true;
	start_new_thread(periodic_update, NULL, "peer-periodic-update");
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
	bool file_asked;
	unsigned int timeouts;
	struct fsnp_peer sp_addr;
};

static struct peer_tcp_state tcp_state;

/*
 * Handler called when a FILE_RES msg is received.
 */
void file_res_rcvd(struct fsnp_file_res *file_res)
{
	uint8_t i = 0;
	struct in_addr addr;

	tcp_state.file_asked = false;
	printf("\nThere are %hhu peers who have the file you're searching.\n You"
		   " can download it from one of them by inserting the string "
	       "'download' from the command line.\n\n", file_res->num_peers);

	slog_info(FILE_LEVEL, "%hhu peers own the file searched", file_res->num_peers);
	for (i = 0; i < file_res->num_peers; i++) {
		addr.s_addr = htonl(file_res->peers[i].ip);
		printf("Peer %hhu: %s:%hu\n", i, inet_ntoa(addr),
				file_res->peers[i].port);
		slog_info(FILE_LEVEL, "Peer %s:%hu", inet_ntoa(addr),
				file_res->peers[i].port);
	}

	PRINT_PEER;
}

static void promote_rcvd(const struct fsnp_promote *promote)
{
	struct fsnp_peer sps[2];
	unsigned n = 0;

	memset(sps, 0, sizeof(struct fsnp_peer) * 2);
	if (promote->sp_port) {
		sps[0].ip = tcp_state.sp_addr.ip;
		sps[0].port = promote->sp_port;
		n++;
		if (promote->sp.ip != 0 && promote->sp.port != 0) {
			memcpy(&sps[1], &promote->sp, sizeof(struct fsnp_peer));
			n++;
		}
	}

	enter_sp_mode(sps, n);
}

/*
 * Check if the superpeer is still alive. If not close the communications and
 * quit the thread
 */
static void is_alive(void)
{
	fsnp_err_t err;
	struct fsnp_alive alive;

	tcp_state.timeouts++;
	slog_debug(FILE_LEVEL, "The peer_tcp_thread's poll has fired its timeout"
	                      " timer. Now the timeouts are %u", tcp_state.timeouts);
	if (tcp_state.timeouts > 4) {
		// the peer didn't contacted us for more than 2 minutes
		slog_warn(STDOUT_LEVEL, "This peer has not received any sign of life"
						  " from the superpeer for more then 2 minutes."
						  " Join another one please.");
		PRINT_PEER;
		tcp_state.quit_loop = true;
		return;
	}

	fsnp_init_alive(&alive);
	err = fsnp_send_tcp_alive(tcp_state.sock, &alive);
	slog_info(FILE_LEVEL, "Sending an alive message to the superpeer from the"
					   " is_alive function");
	if (err == E_PEER_DISCONNECTED) {
		slog_warn(STDOUT_LEVEL, "The superpeer has disconnected itself. Join"
						  " another one please");
		PRINT_PEER;
		tcp_state.quit_loop = true;
	}
}

static void read_sock_msg(void)
{
	struct fsnp_msg *msg = NULL;
	fsnp_err_t err;
	struct fsnp_ack ack;

	msg = fsnp_read_msg_tcp(tcp_state.sock, 0, NULL, &err);
	if (!msg) {
		fsnp_log_err_msg(err, false);
		if (err == E_PEER_DISCONNECTED) {
			tcp_state.quit_loop = true;
		}

		return;
	}

	switch (msg->msg_type) {
		case FILE_RES:
			slog_info(FILE_LEVEL, "file_res msg received. Timeouts before this"
						  " message: %u", tcp_state.timeouts);
			file_res_rcvd((struct fsnp_file_res *)msg);
			tcp_state.timeouts = 0;
			break;

		case ALIVE:
			slog_info(FILE_LEVEL, "Alive msg received. Timeouts before this"
			                       " message: %u", tcp_state.timeouts);
			tcp_state.timeouts = 0;
			fsnp_init_ack(&ack);
			err = fsnp_send_tcp_ack(tcp_state.sock, &ack);
			if (err == E_TIMEOUT) {
				is_alive();
			}

			slog_info(FILE_LEVEL, "ACK sent to the superpeer");
			break;

		case PROMOTE:
			slog_info(FILE_LEVEL, "Promote msg received. Timeouts before this"
						 " message: %u", tcp_state.timeouts);
			promote_rcvd((const struct fsnp_promote *)msg);
			tcp_state.timeouts = 0;

		case ACK:
			slog_info(FILE_LEVEL, "Ack msg received. Timeouts before this "
						  "message: %u", tcp_state.timeouts);
			tcp_state.timeouts = 0;
			break;

		case ERROR:
			slog_warn(STDOUT_LEVEL, "The superpeer has sent an ERROR msg");
			PRINT_PEER;
			tcp_state.timeouts = 0;
			break;

		case LEAVE:
			slog_info(FILE_LEVEL, "Leave msg received");
			tcp_state.timeouts = 0;
			fsnp_init_ack(&ack);
			fsnp_send_tcp_ack(tcp_state.sock, &ack);
			slog_info(FILE_LEVEL, "Ack sent to the superpeer");
			tcp_state.quit_loop = true;
			break;

		default:
			slog_warn(FILE_LEVEL, "Unexpected message type: %d", msg->msg_type);
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
		slog_warn(STDOUT_LEVEL, "The superpeer has disconnected itself. Please"
						  " join another one");
		PRINT_PEER;
		tcp_state.quit_loop = true;
	} else {
		tcp_state.quit_loop = true;
		slog_error(FILE_LEVEL, "revents %hd", revents);
	}
}

#define FILENAME_SIZE 256

/*
 * Read from the pipe the filename and its size
 */
static size_t read_filename_from_pipe(char *msg)
{
	int pipe_read = 0;
	ssize_t r = 0;
	size_t size;
	fsnp_err_t err;

	pipe_read = tcp_state.pipe_fd[READ_END];
	r = fsnp_timed_read(pipe_read, &size, sizeof(size_t), FSNP_TIMEOUT, &err);
	if (r < 0) {
		fsnp_log_err_msg(err, false);
		slog_error(FILE_LEVEL, "Unable to read the length of the filename");
		return 0;
	}

	r = fsnp_timed_read(pipe_read, msg, size, FSNP_TIMEOUT, &err);
	if (r < 0) {
		fsnp_log_err_msg(err, false);
		slog_error(FILE_LEVEL, "Unable to read the filename from the pipe");
		return 0;
	}

	slog_info(FILE_LEVEL, "Filename %s of length %llu has been read from the"
					   " pipe", msg, size);
	return size;
}

/*
 *  Send a who_has message to the superpeer
 */
static void send_file_req(void)
{
	size_t size;
	char msg[FILENAME_SIZE];
	fsnp_err_t err;
	struct fsnp_file_req file_req;
	sha256_t sha;
	struct fsnp_msg *fm = NULL;
#ifdef FSNP_DEBUG
	char key_str[SHA256_BYTES];
	unsigned i = 0;
#endif

	size = read_filename_from_pipe(msg);
	if (size == 0) {
		return;
	}

	if (tcp_state.file_asked) {
		// If the user was quick enough to ask two times for a file stop him here
		slog_info(FILE_LEVEL, "The user tried to download a file while another"
						" request is pending");
		slog_warn(STDOUT_LEVEL, "You're already searching for a file. Wait for"
						  " its response before searching for another one");
		return;
	}

	sha256(msg, size, sha);
	fsnp_init_file_req(&file_req, sha);
#ifdef FSNP_DEBUG
	STRINGIFY_HASH(key_str, sha, i);
	slog_debug(FILE_LEVEL, "SHA-256 of the file searched: %s", key_str);
#endif
	err = fsnp_send_file_req(tcp_state.sock, &file_req);
	slog_info(FILE_LEVEL, "Sending a file_req to the superpeer");
	if (err != E_NOERR) {
		slog_warn(STDOUT_LEVEL, "Unable to send the file request");
		fsnp_log_err_msg(err, false);
		return;
	}

	slog_info(FILE_LEVEL, "Reading superpeer's response");
	fm = fsnp_read_msg_tcp(tcp_state.sock, 0, NULL, &err);
	if (!fm) {
		fsnp_log_err_msg(err, false);
		if (err == E_PEER_DISCONNECTED) {
			tcp_state.quit_loop = true;
		}

		return;
	}

	if (fm->msg_type == ACK) {
		slog_info(FILE_LEVEL, "The superpeer has accepted the file_req");
		tcp_state.file_asked = true;
	} else if (fm->msg_type == ERROR) {
		slog_warn(STDOUT_LEVEL, "The superpeer has refused the request");
		PRINT_PEER;
		tcp_state.file_asked = false;
	} else {
		slog_warn(STDOUT_LEVEL, "Unexpected msg_type from the superpeer: %u",
				fm->msg_type);
		PRINT_PEER;
		tcp_state.file_asked = false;
	}

	free(fm);
}

/*
 * Read a message from the pipe and call the right handler
 */
static void read_pipe_msg(void)
{
	int type = 0;
	ssize_t ret = 0;
	char err_msg[] = "An internal error has occurred. Leaving the P2P network";

	ret = fsnp_read(tcp_state.pipe_fd[READ_END], &type, sizeof(int));
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Unable to read a msg from the pipe");
		printf("%s\n", err_msg);
		PRINT_PEER;
		tcp_state.quit_loop = true;
		return;
	}

	switch (type) {
		case PIPE_QUIT:
			tcp_state.quit_loop = true;
			break;

		case PIPE_WHOHAS:
			send_file_req();
			break;

		case PIPE_DOWNLOAD:
			// TODO: implement
			break;

		default:
			// if we're here something really weird happened. Close everything
			tcp_state.quit_loop = true;
			slog_error(FILE_LEVEL, "Quitting the 'peer_tcp_thread'. An"
						  " unexpected error has occurred");
			printf("%s\n", err_msg);
			PRINT_PEER;
			break;
	}
}

#undef FILENAME_SIZE

/*
 * Handle an event happened in the pipe (read side)
 */
static void pipe_event(short revents)
{
	if (revents & POLLIN || revents & POLLRDBAND || revents & POLLPRI) {
		read_pipe_msg();
	} else {
		slog_error(FILE_LEVEL, "Unexpected revents value: %hu", revents);
		printf("An unexpected error has occurred internally. Leaving the"
		 "superpeer\n");
		PRINT_PEER;
		tcp_state.quit_loop = true;
	}
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
 * Entry point for the thread spawned by 'launch_peer_thread'.
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
	struct fsnp_msg *msg = NULL;

	UNUSED(data);

	slog_info(FILE_LEVEL, "Setting up the poll for the peer_tcp_thread");
	setup_peer_tcp_poll(fds);

	tcp_state.quit_loop = false;
	tcp_state.send_leave_msg = false;
	tcp_state.file_asked = false;

	slog_info(FILE_LEVEL, "Entering the event loop for the peer_tcp_thread");
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
			is_alive();
		} else {
			slog_error(FILE_LEVEL, "poll. Error %d", errno);
			tcp_state.quit_loop = true;
		}
	}

	slog_info(STDOUT_LEVEL, "Leaving the superpeer...");

	if (tcp_state.send_leave_msg) {
		fsnp_init_leave(&leave);
		err = fsnp_send_tcp_leave(tcp_state.sock, &leave);
		slog_info(FILE_LEVEL, "Sending an alive msg to the sp from the"
						" peer_tcp_thread");
		if (err != E_NOERR) {
			fsnp_log_err_msg(err, false);
		}

		// read the ACK
		msg = fsnp_read_msg_tcp(tcp_state.sock, 0, NULL, &err);
		if (!msg) {
			fsnp_log_err_msg(err, false);
		} else if (msg->msg_type != ACK) {
			slog_warn(FILE_LEVEL, "The peer didn't get an ACK after the leave"
						 " msg. It has get instead %u", msg->msg_type);
		} else {
			slog_info(FILE_LEVEL, "The superpeer sent an ACK");
		}

		free(msg);
	}

	close(tcp_state.sock);
	close(tcp_state.pipe_fd[READ_END]);
	close(tcp_state.pipe_fd[WRITE_END]);

	tcp_state.sock = 0;
	tcp_state.pipe_fd[READ_END] = 0;
	tcp_state.pipe_fd[WRITE_END] = 0;

	stop_peer_update_thread();
}

/*
 * Set up 'tcp_state' and spawn the relative thread
 */
static void launch_peer_thread(int sock, const struct fsnp_peer *sp)
{
	int ret = 0;

	ret = pipe(tcp_state.pipe_fd);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "pipe. Error %d", errno);
		printf("An internal error has occurred. The peer will not join a"
		 " superpeer.\n");
		PRINT_PEER;
		close(sock);
		stop_peer_update_thread();
		return;
	}

	tcp_state.sock = sock;
	tcp_state.quit_loop = false;
	tcp_state.send_leave_msg = false;
	memcpy(&tcp_state.sp_addr, sp, sizeof(struct fsnp_peer));
	ret = start_new_thread(peer_tcp_thread, NULL, "peer_tcp_thread");
	if (ret < 0) {
		slog_error(FILE_LEVEL, "unable to start the peer_tcp_thread", errno);
		printf("An internal error has occurred. The peer will not join a"
		       " superpeer.\n");
		PRINT_PEER;
		close(sock);
		close(tcp_state.pipe_fd[READ_END]);
		close(tcp_state.pipe_fd[WRITE_END]);
		stop_peer_update_thread();
	}
}

void join_sp(const struct fsnp_query_res *query_res)
{
	int choice = 0;
	int sock = 0;
	int ret = 0;

	if (is_superpeer()) {
		slog_debug(FILE_LEVEL, "The user has tried to join a sp as sp");
		printf("You're a superpeer, you can't join another superpeer\n");
		PRINT_PEER;
		return;
	}

	if (tcp_state.sock != 0) { // we're already connected to a superpeer
		slog_debug(FILE_LEVEL, "The user has tried to join a sp while he's "
						 "already connected to another one");
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
		slog_warn(STDOUT_LEVEL, "Unable to establish a connection with the "
						  "superpeer");
		PRINT_PEER;
		return;
	}

	ret = send_join_msg(sock);
	if (ret < 0) {
		slog_warn(STDOUT_LEVEL, "Unable to join the superpeer");
		PRINT_PEER;
		close(sock);
		return;
	}

	ret = read_join_res(sock);
	if (ret < 0) {
		slog_warn(STDOUT_LEVEL, "Unable to join the superpeer");
		PRINT_PEER;
		close(sock);
		return;
	}

	launch_peer_thread(sock, &query_res->sp_list[choice]);
}

void peer_ask_file(const char *filename, size_t size)
{
	ssize_t ret = 0;
	int to_write = PIPE_WHOHAS;
	static const char err_msg[] = "unable to send WHO_HAS";

	ret = fsnp_write(tcp_state.pipe_fd[WRITE_END], &to_write, sizeof(int));
	if (ret < 0) {
		slog_error(FILE_LEVEL, "%s", err_msg);
		return;
	}

	ret = fsnp_write(tcp_state.pipe_fd[WRITE_END], &size, sizeof(size_t));
	if (ret < 0) {
		slog_error(FILE_LEVEL, "%s", err_msg);
		return;
	}

	ret = fsnp_write(tcp_state.pipe_fd[WRITE_END], filename, size);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "%s", err_msg);
		return;
	}
}

bool file_already_asked(void)
{
	return tcp_state.file_asked;
}

int get_peer_sock(void)
{
	int sock = tcp_state.sock;
	return sock;
}

void leave_sp(void)
{
	ssize_t ret = 0;
	int to_write = PIPE_QUIT;

	tcp_state.send_leave_msg = true;
	ret = fsnp_write(tcp_state.pipe_fd[WRITE_END], &to_write, sizeof(int));
	if (ret < 0) {
		tcp_state.quit_loop = true; // force the thread to quit
		slog_error(STDOUT_LEVEL, "Forcing to quit peer_tcp_thread for an"
						   " internal error");
		slog_error(FILE_LEVEL, "fsnp_write. Error %d", errno);
	}
}

#undef POLL_ALIVE_TIMEOUT
#undef READ_END
#undef WRITE_END
#undef SOCK
#undef PIPE
#undef PIPE_QUIT
#undef PIPE_DOWNLOAD
#undef PIPE_WHO_HAS