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

#include "peer/peer.h"
#include "peer/superpeer.h"
#include "peer/port.h"
#include "peer/stdin.h"
#include "peer/thread_manager.h"
#include "peer/file_manager.h"
#include "peer/peer-superpeer.h" // for stop_update_thread

#include "fsnp/fsnp.h"

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
};

static struct state state;

static const char err_lock_msg[] = "Unable to lock state_mtx.\n The data from"
								   " now on can be compromised. It's suggested"
		                           " to restart the peer\n";
static const char err_unlock_msg[] = "Unable to unlock state_mtx.\n The data"
									 " from now on can be compromised. It's"
		                             " suggested to restart the peer\n";

void add_poll_sp_sock(int tcp_sock)
{
	if (pthread_mutex_lock(&state.state_mtx)) {
		fprintf(stderr, err_lock_msg);
		PRINT_PEER;
	}

	state.fds[POLL_SP_TCP].fd = tcp_sock;
	state.fds[POLL_SP_TCP].events = POLLIN | POLLPRI;
	state.sp = true;

	state.num_fd = SP_POLLFD_NUM; // add the socket to the poll count

	if (pthread_mutex_unlock(&state.state_mtx)) {
		fprintf(stderr, err_unlock_msg);
		PRINT_PEER;
	}
}

void rm_poll_sp_sock(void)
{
	if (!is_superpeer()) { // it's here to avoid to lock twice the same mtx
		return;
	}

	if (pthread_mutex_lock(&state.state_mtx)) {
		fprintf(stderr, err_lock_msg);
		PRINT_PEER;
	}

	close(state.fds[POLL_SP_TCP].fd);

	state.fds[POLL_SP_TCP].fd = 0;
	state.fds[POLL_SP_TCP].events = 0;
	state.sp = false;

	// remove the sockets from the poll interface
	state.num_fd = SP_POLLFD_NUM - 1;

	if (pthread_mutex_unlock(&state.state_mtx)) {
		fprintf(stderr, err_unlock_msg);
		PRINT_PEER;
	}

	set_udp_sp_port(0);
	set_tcp_sp_port(0);
}

int get_sp_tcp_sock(void)
{
	if (!is_superpeer()) {
		return 0;
	}

	if (pthread_mutex_lock(&state.state_mtx)) {
		fprintf(stderr, err_lock_msg);
		PRINT_PEER;
	}

	int sock = state.fds[POLL_SP_TCP].fd;

	if (pthread_mutex_unlock(&state.state_mtx)) {
		fprintf(stderr, err_unlock_msg);
		PRINT_PEER;
	}

	return sock;
}

bool is_superpeer(void)
{
	bool res;

	if (pthread_mutex_lock(&state.state_mtx)) {
		fprintf(stderr, err_lock_msg);
		PRINT_PEER;
	}

	res = state.sp;

	if (pthread_mutex_unlock(&state.state_mtx)) {
		fprintf(stderr, err_unlock_msg);
		PRINT_PEER;
	}

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
	state.tcp_sp_port = port;
}

void set_udp_sp_port(in_port_t port)
{
	state.udp_sp_port = port;
}

in_port_t get_udp_sp_port(void)
{
	return state.udp_sp_port;
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
		perror("Unable to set up the signal handler for ^C.\n"
		       "You can still exit by entering 'quit' from the command line.\n");
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
		perror("poll");
		state.should_exit = true;
	}
}

#define POLL_TIMEOUT 10000 // ms

int peer_main(bool localhost)
{
	int ret = 0;

	printf("Initializing the peer...\n");

	state.localhost = localhost;
	if (pthread_mutex_init(&state.state_mtx, NULL)) {
		fprintf(stderr, "Unable to initialize tnum_fd_mtx.\nAborting\n");
		exit(EXIT_FAILURE);
	}

	printf("Initializing the thread manager...\n");
	ret = init_thread_manager();
	if (ret < 0) {
		fprintf(stderr, "Unable to start the thread manager.\nAborting");
		pthread_mutex_destroy(&state.state_mtx);
		exit(EXIT_FAILURE);
	}

	printf("Initializing the file manager...\n");
	ret = init_file_manager();
	if (ret < 0) {
		fprintf(stderr, "Unable to start the file manager.\nAborting");
		pthread_mutex_destroy(&state.state_mtx);
		exit(EXIT_FAILURE);
	}

	printf("Setting up the 'ctrl C' signal handler...\n");
	setup_signal_handler();
	init_stdin();
	state.num_fd = PEER_POLLFD_NUM;
	printf("Setting up the poll interface...\n");
	setup_poll();

	printf("The peer is successfully initialized!\n");
	PRINT_PEER;
	while (!state.should_exit) {
		ret = poll(state.fds, state.num_fd, POLL_TIMEOUT);
		handle_poll_ret(ret);
	}

	printf("Quitting...\n");
	// TODO: free all the resources of the struct library
	if (is_superpeer()) {
		printf("Closing the superpeer's sockets...\n");
		exit_sp_mode();
	} else if (get_peer_sock() != 0) {
		leave_sp();
	}

	printf("Closing the thread manager...\n");
	close_thread_manager();
	printf("Closing the file manager...\n");
	close_file_manager();
	close_stdin();
	pthread_mutex_destroy(&state.state_mtx);
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