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
#include <signal.h>
#include <stdbool.h>
#include <poll.h>
#include <sys/socket.h>
#include <memory.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include "peer/peer.h"
#include "peer/superpeer.h"
#include "peer/port.h"
#include "peer/stdin.h"
#include "peer/thread_manager.h"
#include "peer/file_manager.h"
#include "peer/peer-superpeer.h"

#include "fsnp/fsnp.h"

#include "slog/slog.h"

#define POLLFD_NUM 2

#define PEER_POLLFD_NUM 1
#define SP_POLLFD_NUM 2

#define POLL_STDIN 0
#define POLL_SP_TCP 1

struct state {
	bool should_exit;
	nfds_t num_fd;
	pthread_mutex_t state_mtx;
	struct pollfd fds[POLLFD_NUM];
	in_port_t tcp_sp_port;
	in_port_t udp_sp_port;
	bool localhost;
	bool sp;
	struct fsnp_peer server_addr;
	in_addr_t peer_ip;
};

static struct state state;

static const char err_lock_msg[] = "Unable to lock state_mtx. The data from"
								   " now on can be compromised. It's suggested"
		                           " to restart the peer";
static const char err_unlock_msg[] = "Unable to unlock state_mtx. The data"
									 " from now on can be compromised. It's"
		                             " suggested to restart the peer";

#define LOCK_STATE  if (pthread_mutex_lock(&state.state_mtx)) { \
						slog_error(STDOUT_LEVEL, "%s", err_lock_msg); \
						PRINT_PEER; \
					}

#define UNLOCK_STATE    if (pthread_mutex_unlock(&state.state_mtx)) { \
							slog_error(STDOUT_LEVEL, "%s", err_unlock_msg); \
							PRINT_PEER; \
						}

void add_poll_sp_sock(int tcp_sock)
{
	LOCK_STATE

	state.fds[POLL_SP_TCP].fd = tcp_sock;
	state.fds[POLL_SP_TCP].events = POLLIN | POLLPRI;
	state.sp = true;

	state.num_fd = SP_POLLFD_NUM; // add the socket to the poll count

	UNLOCK_STATE;
}

void rm_poll_sp_sock(void)
{
	if (!is_superpeer()) { // it's here to avoid to lock twice the same mtx
		return;
	}

	LOCK_STATE;

	close(state.fds[POLL_SP_TCP].fd);

	state.fds[POLL_SP_TCP].fd = 0;
	state.fds[POLL_SP_TCP].events = 0;
	state.sp = false;

	// remove the sockets from the poll interface
	state.num_fd = SP_POLLFD_NUM - 1;

	UNLOCK_STATE;

	set_udp_sp_port(0);
	set_tcp_sp_port(0);
}

int get_tcp_sp_sock(void)
{
	if (!is_superpeer()) {
		return 0;
	}

	LOCK_STATE;

	int sock = state.fds[POLL_SP_TCP].fd;

	UNLOCK_STATE;

	return sock;
}

bool is_superpeer(void)
{
	bool res;

	LOCK_STATE;

	res = state.sp;

	UNLOCK_STATE;

	return res;
}

bool is_localhost(void)
{
	return state.localhost;
}

in_port_t get_tcp_sp_port(void)
{
	return state.tcp_sp_port;
}

void set_tcp_sp_port(in_port_t port)
{
	slog_info(FILE_LEVEL, "Setting tcp_sp_port to %hu", port);
	state.tcp_sp_port = port;
}

void set_udp_sp_port(in_port_t port)
{
	slog_info(FILE_LEVEL, "Setting udp_sp_port to %hu", port);
	state.udp_sp_port = port;
}

in_port_t get_udp_sp_port(void)
{
	return state.udp_sp_port;
}

void set_server_addr(const struct fsnp_peer *addr)
{
	struct in_addr a;
	LOCK_STATE;

	a.s_addr = htonl(addr->ip);
	slog_info(FILE_LEVEL, "Setting server_addr to %s:%hu", inet_ntoa(a),
			addr->port);
	memcpy(&state.server_addr, addr, sizeof(struct fsnp_peer));

	UNLOCK_STATE;
}

void get_server_addr(struct fsnp_peer *addr)
{
	LOCK_STATE;

	memcpy(addr, &state.server_addr, sizeof(struct fsnp_peer));

	UNLOCK_STATE;
}

void set_peer_ip(in_addr_t peer_ip)
{
	struct in_addr a;

	a.s_addr = htonl(peer_ip);
	slog_info(FILE_LEVEL, "Setting peer_ip to %s", inet_ntoa(a));
	state.peer_ip = peer_ip;
}

in_addr_t get_peer_ip(void)
{
	return state.peer_ip;
}

void quit_peer(void)
{
	state.should_exit = true;
}

static void termination_handler(int signum)
{
	UNUSED(signum);
	state.should_exit = true;
}

/*
 * Configure the server for handling the Ctrl-C signal.
 */
static void setup_signal_handler(void)
{
	int err = 0;
	struct sigaction s;

	sigemptyset(&s.sa_mask);
	s.sa_handler = termination_handler;
	s.sa_flags = SA_RESTART;
	err = sigaction(SIGINT, &s, NULL);
	if (err < 0) {
		slog_warn(STDOUT_LEVEL, "Unable to set up the signal handler for ^C. "
		       "You can still exit by entering 'quit' from the command line.");
	}
}

static void setup_poll(void)
{
	memset(state.fds, 0, sizeof(struct pollfd) * PEER_POLLFD_NUM);

	state.fds[POLL_STDIN].fd = STDIN_FILENO;
	state.fds[POLL_STDIN].events = POLLIN | POLLPRI;
}

static void handle_poll_ret(int ret)
{
	if (ret > 0) {
		if (state.fds[POLL_STDIN].revents) {
			stdin_event();
			state.fds[POLL_STDIN].revents = 0;
		}

		if (is_superpeer()) {
			if (state.fds[POLL_SP_TCP].revents) {
				sp_tcp_sock_event(state.fds[POLL_SP_TCP].revents);
				state.fds[POLL_SP_TCP].revents = 0;
			}
		}

	} else if (ret == 0) { // timeout
		join_threads_if_any();
	} else {
		if (errno != EINTR) {
			slog_error(STDOUT_LEVEL, "poll error %d", errno);
		} else {
			slog_info(FILE_LEVEL, "Poll has been interrupted by a signal");
		}
		state.should_exit = true;
	}
}

#define POLL_TIMEOUT 10000 // ms

int peer_main(bool localhost)
{
	int ret = 0;

	slog_info(STDOUT_LEVEL, "Initializing the peer...");

	state.localhost = localhost;
	if (pthread_mutex_init(&state.state_mtx, NULL)) {
		slog_error(STDOUT_LEVEL, "Unable to initialize tnum_fd_mtx. Aborting");
		exit(EXIT_FAILURE);
	}

	slog_info(STDOUT_LEVEL, "Initializing the thread manager...");
	ret = init_thread_manager();
	if (ret < 0) {
		slog_error(STDOUT_LEVEL, "Unable to start the thread manager. Aborting");
		pthread_mutex_destroy(&state.state_mtx);
		exit(EXIT_FAILURE);
	}

	slog_info(STDOUT_LEVEL, "Initializing the file manager...");
	ret = init_file_manager();
	if (ret < 0) {
		slog_error(STDOUT_LEVEL, "Unable to start the file manager. Aborting");
		pthread_mutex_destroy(&state.state_mtx);
		exit(EXIT_FAILURE);
	}

	slog_info(STDOUT_LEVEL, "Setting up the ^C signal handler...");
	setup_signal_handler();
	slog_info(STDOUT_LEVEL, "Initializing the stdin subsystem...");
	init_stdin();
	state.num_fd = PEER_POLLFD_NUM;
	slog_info(STDOUT_LEVEL, "Setting up the poll interface...");
	setup_poll();

	slog_info(STDOUT_LEVEL, "The peer is successfully initialized!");
	PRINT_PEER;
	while (!state.should_exit) {
		ret = poll(state.fds, state.num_fd, POLL_TIMEOUT);
		handle_poll_ret(ret);
		if (ret < 0 && errno == EINTR) {
			ret = 0;
		}
	}

	slog_info(STDOUT_LEVEL, "Quitting...");
	// TODO: free all the resources of the struct library
	if (is_superpeer()) {
		slog_info(FILE_LEVEL, "Exiting sp mode");
		exit_sp_mode();
	} else if (get_peer_sock() != 0) {
		leave_sp();
	}

	slog_info(STDOUT_LEVEL, "Closing the thread manager...");
	close_thread_manager();
	slog_info(STDOUT_LEVEL, "Closing the file manager...");
	close_file_manager();
	slog_info(STDOUT_LEVEL, "De-initializing the stdin subsystem");
	close_stdin();
	pthread_mutex_destroy(&state.state_mtx);
	slog_close();
	if (ret >= 0) { // just return a standard value
		printf("\nThe peer is exiting successfully!\n\n");
		ret = EXIT_SUCCESS;
	} else {
		printf("\nThe peer is exiting for an error!\n\n");
		ret = EXIT_FAILURE;
	}

	return ret;
}

#undef POLL_TIMEOUT

#undef PEER_POLLFD_NUM

#undef POLL_STDIN
#undef POLL_SP_TCP