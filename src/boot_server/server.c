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
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#include "compiler.h"

#include "boot_server/server.h"
#include "boot_server/sp_manager.h"
#include "boot_server/server_sock.h"

#include "fsnp/fsnp.h"

#include "struct/linklist.h"

#include "slog/slog.h"

#define PEER_POLLFD_NUM 2
#define SOCK_FD 0
#define STDIN_FD 1

#define MAX_STDIN_SIZE 16UL

static bool should_exit = false;

static int sock = 0;

static void termination_handler(int signum)
{
	UNUSED(signum);
	should_exit = true;
}

/*
 * Configure the server for handling the Ctrl-C signal.
 */
static void setup_signal_handler(void)
{
	int err;
	struct sigaction s;

	sigemptyset(&s.sa_mask);
	s.sa_handler = termination_handler;
	s.sa_flags = SA_RESTART;
	err = sigaction(SIGINT, &s, NULL);
	if (err < 0) {
		slog_warn(STDOUT_LEVEL, "Unable to set up the signal handler for ^C. "
						  "You can still exit by entering 'quit' from the "
						  "command line.");
	}
}

static int create_server_socket(in_port_t port, bool localhost)
{
	in_port_t sock_port = port;
	int ret = 0;

	sock = fsnp_create_bind_tcp_sock(&sock_port, localhost);
	if (sock < 0) {
		slog_error(FILE_LEVEL, "Unable to create the server socket."
		                         " Error: %d", errno);
		return -1;
	}

	if (sock_port != port) {
		slog_warn(STDOUT_LEVEL, "The socket wasn't created on the port %hu but"
						  " on the port %hu", port, sock_port);
	}

	ret = listen(sock, FSNP_BACKLOG);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "listen: error %d", errno);
		return -1;
	}

	slog_info(STDOUT_LEVEL, "Server socket successfully created!");

	return 0;
}

static void pollfd_setup(struct pollfd *pollfd)
{
	pollfd[SOCK_FD].fd = sock;
	pollfd[SOCK_FD].events = POLLIN;
	pollfd[STDIN_FD].fd = STDIN_FILENO;
	pollfd[STDIN_FD].events = POLLIN;
}

static int list_print_iterator(void *val, size_t idx, void *user)
{
	UNUSED(idx);
	UNUSED(user);
	struct fsnp_server_sp *sp = (struct fsnp_server_sp *)val;

	sp->addr.s_addr = htonl(sp->addr.s_addr);
	printf("%-16s | %-16hu | %-16hu\n", inet_ntoa(sp->addr), sp->p_port, sp->sp_port);
	return GO_AHEAD; // Continue the iteration
}

static void print_sp(void)
{
	linked_list_t *list = NULL;

	list = read_all_sp();
	if (!list) {
		slog_warn(STDOUT_LEVEL, "Unable to read the list");
		return;
	}

	printf("%-16s | %-16s | %-16s\n", "IP", "peer port", "superpeer port\n");
	list_foreach_value(list, list_print_iterator, NULL);
	printf("\n");
	list_destroy(list);
}

static void print_help(void)
{
	printf("%-20s %-30s\n"
		   "%-20s %-30s\n",
		   "list_sp", "Show the list of superpeers known by the server",
		   "quit", "Exit the boot server executable");
}

/*
 * Remove any undesired character from the standard input
 */
static void cleanup_stdin(void)
{
	int c = 0;

	if (!feof(stdin)) {
		return;
	}

	while ((c = getchar()) != '\n') {
		;
	}
}

/*
 * Function called whenever there's something to read in the stdin
 */
static void server_stdin_handler(void)
{
	const char quit[] = "quit\n";
	const char list_sp[] = "list_sp\n";
	const char help[] = "help\n";
	char user_msg[MAX_STDIN_SIZE];

	memset(user_msg, 0, MAX_STDIN_SIZE);

	if (!fgets(user_msg, MAX_STDIN_SIZE, stdin)) {
		slog_error(STDOUT_LEVEL, "Error %d for fgets", errno);
	}

	slog_debug(FILE_LEVEL, "server_stdin_handler: msg \"%s\"", user_msg);
	if (!strncmp(user_msg, quit, sizeof(quit))) {
		should_exit = true;
		return;
	} else if (!strncmp(user_msg, list_sp, sizeof(list_sp))) {
		print_sp();
	} else if (!strncmp(user_msg, help, sizeof(help))) {
		print_help();
	} else {
		fprintf(stderr, "?\n");
	}

	PRINT_SERVER;
	cleanup_stdin();
}

#undef MAX_STDIN_SIZE

/*
 * Handle the return from the poll
 */
static void handle_poll_ret(struct pollfd *pollfd, int ret)
{
	if (ret > 0) {
		if (pollfd[SOCK_FD].revents) {
			server_socket_handler(sock, pollfd[SOCK_FD].revents);
		}

		if (pollfd[STDIN_FD].revents) {
			server_stdin_handler();
		}

		PRINT_SERVER;
	} else if (ret < 0) {
		if (errno != EINTR) {
			slog_error(STDOUT_LEVEL, "poll: errno %d", errno);
		}

		should_exit = true;
	}
}

#define POLL_TIMEOUT 1000 // ms
int server_main(in_port_t port, bool localhost)
{
	int ret = 0;
	struct pollfd pollfd[PEER_POLLFD_NUM];

	slog_info(STDOUT_LEVEL, "Starting server initialization");
	slog_info(STDOUT_LEVEL, "Initializing the server socket");
	ret = create_server_socket(port, localhost);
	if (ret < 0) {
		slog_error(STDOUT_LEVEL, "Unable to create the server socket. Aborting");
		return ret;
	}

	slog_info(STDOUT_LEVEL, "Initializing the sp_manager");
	ret = init_sp_manager();
	if (ret < 0) {
		slog_error(STDOUT_LEVEL, "Unable to setup the sp manager. Aborting");
		close(sock);
		return ret;
	}

	slog_info(STDOUT_LEVEL, "Setting up the poll interface");
	pollfd_setup(pollfd);

	slog_info(STDOUT_LEVEL, "Setting up the ^C signal handler");
	setup_signal_handler();

	slog_info(STDOUT_LEVEL, "The server is successfully initialized");
	printf("\n");
	PRINT_SERVER;
	while (!should_exit) {
		ret = poll(pollfd, PEER_POLLFD_NUM, POLL_TIMEOUT);
		handle_poll_ret(pollfd, ret);
	}

	slog_info(STDOUT_LEVEL, "Exiting the boot_server executable...");
	slog_info(STDOUT_LEVEL, "Closing the server sock");
	close(sock);
	slog_info(STDOUT_LEVEL, "Closing the sp_manager");
	close_sp_manager();
	slog_close();

	if (ret >= 0) { // return a standard value
		ret = EXIT_SUCCESS;
	} else {
		ret = EXIT_FAILURE;
	}

	return ret;
}

#undef POLL_TIMEOUT
#undef PEER_POLLFD_NUM
#undef SOCK_FD
#undef STDIN_FD
#undef MAX_STDIN_SIZE