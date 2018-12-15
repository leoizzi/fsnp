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
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <errno.h>

#include "peer/peer.h"
#include "peer/peer-server.h"
#include "peer/superpeer.h"
#include "peer/port.h"
#include "peer/keys_cache.h"
#include "peer/thread_manager.h"
#include "peer/peer-superpeer.h"
#include "peer/superpeer-peer.h"
#include "peer/superpeer-superpeer.h"
#include "peer/stdin.h"
#include "peer/fake_peer.h"

#include "fsnp/fsnp.h"

#include "struct/linklist.h"

#include "slog/slog.h"

#define SP_BACKLOG 128

/*
 * This list doesn't have a free callback because it shares the content with
 * a 'sp_tcp_thread'. The thread will free the memory when it's about to close
 */
static linked_list_t *known_peers = NULL;

/*
 * Used by the superpeer to be able to ask files for himself inside the overlay
 * network
 */
static struct peer_info *fake_peer = NULL;

/*
 * Create the superpeer's sockets and enter the overlay network
 */
static bool initialize_sp(struct fsnp_peer *sps, unsigned n, int serv_sock)
{
	int udp = 0;
	int tcp = 0;
	int ret = 0;
	in_port_t udp_port = SP_UDP_PORT;
	in_port_t tcp_port = SP_TCP_PORT;
	bool localhost = is_localhost();

	slog_info(FILE_LEVEL, "Creating and binding the sp's TCP socket");
	tcp = fsnp_create_bind_tcp_sock(&tcp_port, localhost);
	if (tcp < 0) {
		slog_error(FILE_LEVEL, "Unable to create/bind the TCP socket. Error: %d", errno);
		return false;
	}

	slog_info(FILE_LEVEL, "Creating and binding the sp's UDP socket");
	udp = fsnp_create_bind_udp_sock(&udp_port, localhost);
	if (udp < 0) {
		slog_error(FILE_LEVEL, "Unable to create/bind the UDP socket. Error: %d", errno);
		close(tcp);
		return false;
	}

#ifdef FSNP_DEBUG
bool print_peer = false;

	if (tcp_port != SP_TCP_PORT) {
		slog_warn(STDOUT_LEVEL, "Unable to bind the superpeer TCP socket to the "
						  "port %hu. The port %hu has been used instead",
		                  (in_port_t)SP_TCP_PORT, tcp_port);
		print_peer = true;
	}

	if (udp_port != SP_UDP_PORT) {
		slog_warn(STDOUT_LEVEL, "Unable to bind the superpeer UDP socket to the"
						  " port %hu. The port %hu has been used instead",
		                  (in_port_t)SP_UDP_PORT, udp_port);
		print_peer = true;
	}

	if (print_peer) {
		PRINT_PEER;
	}
#endif

	ret = listen(tcp, SP_BACKLOG);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Unable to start listening on the sp's TCP port.");
		close(tcp);
		close(udp);
		PRINT_PEER;
		return false;
	}

	set_udp_sp_port(udp_port);
	set_tcp_sp_port(tcp_port);

	if (get_peer_sock() != 0) {
		// We're getting promoted, leave the superpeer before going forward
		leave_sp();
	}

	ret = enter_sp_network(udp, sps, n);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Unable to enter the superpeer network");
		close(tcp);
		close(udp);
		set_udp_sp_port(0);
		set_tcp_sp_port(0);
		PRINT_PEER;
		return false;
	}

	ret = add_sp_to_server(serv_sock);
	if (ret < 0) {
		fprintf(stderr, "Unable to contact the server for add this superpeer to"
		                " its list. Please join again a superpeer");
		exit_sp_network();
		close(tcp);
		close(udp);
		set_udp_sp_port(0);
		set_tcp_sp_port(0);
		return false;
	}

	fake_peer = create_fake_peer_info();
	ret = start_new_thread(fake_peer_info_thread, fake_peer,
			"fake-peer-info-thread");
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Unable to start fake-peer-info thread");
		close(fake_peer->pipefd[WRITE_END]);
		close(fake_peer->pipefd[READ_END]);
		free(fake_peer);
		fake_peer = NULL;
	}
	add_poll_sp_sock(tcp);
	return true;
}

/*
 * Write into the pipe of a thread who's communicating with a peer to promote
 * him
 */
static void promote_peer(void)
{
	int msg = PIPE_PROMOTE;
	ssize_t w = 0;
	struct peer_info *to_promote = NULL;

	to_promote = list_shift_value(known_peers);
	slog_info(FILE_LEVEL, "Promoting peer %s", to_promote->pretty_addr);
	w = fsnp_write(to_promote->pipefd[WRITE_END], &msg, sizeof(int));
	if (w < 0) {
		slog_error(FILE_LEVEL, "fsn_write error %d", errno);
	}
}

static bool accept_conn = true;

/*
 * Accept a new peer, establishing a TCP connection with him.
 * If the number of peers is greater than MAX_KNOWN_PEER promote the peer at the
 * head of 'known_peers'
 */
static void accept_peer(void)
{
	int s = 0;
	int peer_sock = 0;
	struct sockaddr_in addr;
	socklen_t socklen = sizeof(struct sockaddr_in);
	struct peer_info *peer_info = NULL;
	size_t num_peers = 0;
	int ret = 0;
	int added = 0;

	if (!accept_conn) {
		slog_info(FILE_LEVEL, "Refusing a new connection on the sp's TCP socket");
		return;
	}

	s = get_tcp_sp_sock();
	memset(&addr, 0, socklen);
	slog_info(FILE_LEVEL, "Accepting a new connection on the sp's TCP socket");
	peer_sock = accept(s, (struct sockaddr *)&addr, &socklen);
	if (peer_sock < 0) {
		slog_error(FILE_LEVEL, "Unable to accept the connection. Error %d", errno);
		return;
	}

	addr.sin_port = ntohs(addr.sin_port);
	slog_info(FILE_LEVEL, "Superpeer contacted by peer %s:%hu",
			inet_ntoa(addr.sin_addr), addr.sin_port);
	addr.sin_addr.s_addr = ntohl(addr.sin_addr.s_addr);
	peer_info = malloc(sizeof(struct peer_info));
	if (!peer_info) {
		close(peer_sock);
		slog_error(FILE_LEVEL, "malloc error %d", errno);
		return;
	}

	peer_info->addr.port = addr.sin_port;
	memset(peer_info->pretty_addr, 0, sizeof(char) * 32);
	peer_info->addr.ip = addr.sin_addr.s_addr;
	addr.sin_addr.s_addr = htonl(addr.sin_addr.s_addr);
	snprintf(peer_info->pretty_addr, sizeof(char) * 32, "%s:%hu",
			inet_ntoa(addr.sin_addr), peer_info->addr.port);
	peer_info->sock = peer_sock;
	peer_info->joined = false;
	peer_info->timeouts = 0;
	ret = pipe(peer_info->pipefd);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "pipe error %d", errno);
		close(peer_sock);
		free(peer_info);
		return;
	}

	added = list_push_value(known_peers, peer_info);
	if (ret < 0) {
		slog_warn(FILE_LEVEL, "Unable to add the peer to the known_peer_list");
	}

	ret = start_new_thread(sp_tcp_thread, peer_info, "sp_tcp_thread");
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Unable to start 'sp_tcp_thread' for peer %s:%hu",
				inet_ntoa(addr.sin_addr), addr.sin_port);
		close(peer_sock);
		if (added == 0) {
			list_pop_value(known_peers);
		}

		free(peer_info);
		PRINT_PEER;
	}

	num_peers = list_count(known_peers);
	if (num_peers > MAX_KNOWN_PEER) {
		promote_peer();
	}
}

void sp_tcp_sock_event(short revents)
{
	if (revents & POLLIN || revents & POLLRDBAND || revents & POLLPRI) {
		accept_peer();
	} else {
		slog_warn(FILE_LEVEL, "Unexpected revents %d [TCP sp socket]", revents);
	}
}

void sp_ask_file(const char *filename, size_t size)
{
	int msg = PIPE_WHOHAS;
	sha256_t key;
	fsnp_err_t err;
	ssize_t w = 0;

	w = fsnp_timed_write(fake_peer->pipefd[WRITE_END], &msg, sizeof(int),
			FSNP_TIMEOUT, &err);
	if (w < 0) {
		slog_error(FILE_LEVEL, "Unable to write PIPE_WHOHAS into fake-peer's pipe");
		fsnp_log_err_msg(err, false);
		return;
	}

	sha256(filename, size, key);
	w = fsnp_timed_write(fake_peer->pipefd[WRITE_END], key, sizeof(sha256_t),
			FSNP_TIMEOUT, &err);
	if (w < 0) {
		slog_error(FILE_LEVEL, "Unable to write into fake-peer's pipe the file hash");
		fsnp_log_err_msg(err, false);
	}
}

/*
 * Iterate over known_peers to find to who send the error
 */
static int communicate_error_iterator(void *item, size_t idx, void *user)
{
	struct peer_info *info = (struct peer_info *)item;
	struct fsnp_peer *peer = (struct fsnp_peer *)user;
	ssize_t w = 0;
	int msg = PIPE_ERROR;
	fsnp_err_t err;

	UNUSED(idx);

	if (!memcmp(&info->addr, peer, sizeof(struct fsnp_peer))) {
		slog_info(FILE_LEVEL, "Communicating to %s about the error");
		w = fsnp_timed_write(info->pipefd[WRITE_END], &msg, sizeof(int), 0, &err);
		if (w < 0) {
			fsnp_log_err_msg(err, false);
		}

		return STOP;
	}

	return GO_AHEAD;
}

void communicate_error_to_peer(struct fsnp_peer *peer)
{
	int ret = 0;

	ret = communicate_error_iterator(fake_peer, 0, peer);
	if (ret == STOP) {
		return;
	}

	list_foreach_value(known_peers, communicate_error_iterator, peer);
}

struct communicate_whohas_data {
	struct fsnp_whohas whohas;
	struct fsnp_peer requester;
};

/*
 * Write into the pipe the result of whohas
 */
static void pipe_write_file_res(const struct peer_info *info,
								const struct communicate_whohas_data *data)
{
	int msg = PIPE_FILE_RES;
	ssize_t w = 0;
	fsnp_err_t err;

	w = fsnp_timed_write(info->pipefd[WRITE_END], &msg, sizeof(int), FSNP_TIMEOUT,
	                     &err);
	if (w < 0) {
		slog_error(FILE_LEVEL, "Unable to write PIPE_FILE_RES in the pipe");
		fsnp_log_err_msg(err, false);
	}

	w = fsnp_timed_write(info->pipefd[WRITE_END], &data->whohas,
	                     sizeof(struct fsnp_whohas), FSNP_TIMEOUT, &err);
	if (w < 0) {
		slog_error(FILE_LEVEL, "Unable to communicate to peer %s about the"
		                       " search results", info->pretty_addr);
		fsnp_log_err_msg(err, false);
	}
}

/*
 * Iterate over the peer_info struct contained in known_peers for writing into
 * a peer's thread pipe the result of the whohas search
 */
static int communicate_whohas_iterator(void *item, size_t idx, void *user)
{
	struct peer_info *info = (struct peer_info *)item;
	struct communicate_whohas_data *data = (struct communicate_whohas_data *)user;

	UNUSED(idx);

	if (!memcmp(&info->addr, &data->requester, sizeof(struct fsnp_peer))) {
		slog_info(FILE_LEVEL, "Communicating to %s about the search results",
				info->pretty_addr);
		pipe_write_file_res(info, data);
		return STOP;
	} else {
		return GO_AHEAD;
	}
}

void communicate_whohas_result_to_peer(const struct fsnp_whohas *whohas,
                                       const struct fsnp_peer *requester)
{
	struct communicate_whohas_data data;
	int ret = 0;

	memcpy(&data.whohas, whohas, sizeof(struct fsnp_whohas));
	memcpy(&data.requester, requester, sizeof(struct fsnp_peer));
	ret = communicate_whohas_iterator(fake_peer, 0, &data);
	if (ret == STOP) {
		return;
	}

	list_foreach_value(known_peers, communicate_whohas_iterator, &data);
}

/*
 * Iterate over "known_peers" in order to remove from the list the peer that
 * matches the one passed in "user".
 */
static int rm_peer_callback(void *item, size_t idx, void *user)
{
	struct peer_info *info = (struct peer_info *)item;
	struct fsnp_peer *peer = (struct fsnp_peer *)user;

	UNUSED(idx);

	if (info->addr.ip == peer->ip) {
		if (info->addr.port == peer->port) {
			return REMOVE_AND_STOP;
		} else {
			return GO_AHEAD;
		}
	} else {
		return GO_AHEAD;
	}
}

void rm_peer_from_list(struct fsnp_peer *peer)
{
	list_foreach_value(known_peers, rm_peer_callback, peer);
}

bool enter_sp_mode(struct fsnp_peer *sps, unsigned n, int serv_sock)
{
	bool ret = false;
	char err_msg[] = "Unable to enter the sp_mode";

	slog_info(FILE_LEVEL, "Entering the sp_mode...");
	slog_info(FILE_LEVEL, "Initializing the file cache");
	ret = init_keys_cache();
	if (!ret) {
		printf("%s\n", err_msg);
		PRINT_PEER;
		return false;
	}

	slog_info(FILE_LEVEL, "Creating the known_peers list");
	known_peers = list_create();
	if (!known_peers) {
		close_keys_cache();
		printf("%s\n", err_msg);
		PRINT_PEER;
		return false;
	}

	accept_conn = true;
	ret = initialize_sp(sps, n, serv_sock);
	if (!ret) {
		close_keys_cache();
		list_destroy(known_peers);
		printf("%s\n", err_msg);
		PRINT_PEER;
		return false;
	}

	slog_info(STDOUT_LEVEL, "You're a superpeer");
	return true;
}

/*
 * For each thread spawned for a peer tell it to quit
 */
static int quit_peer_threads_iterator(void *item, size_t idx, void *user)
{
	struct peer_info *info = (struct peer_info *)item;
	ssize_t w = 0;
	int msg = PIPE_QUIT;

	UNUSED(idx);
	UNUSED(user);

	w = fsnp_write(info->pipefd[WRITE_END], &msg, sizeof(int));
	if (w < 0) {
		slog_warn(FILE_LEVEL, "Unable to communicate to the 'sp_tcp_thread' of"
						" peer %s to quit", info->pretty_addr);
	}

	return GO_AHEAD;
}

void quit_all_peers(void)
{
	slog_info(FILE_LEVEL, "Leaving all the peers");
	list_foreach_value(known_peers, quit_peer_threads_iterator, NULL);
}

/*
 * Tell to the fake-peer-info-thread to quit
 */
static void quit_fake_peer_info_thread(void)
{
	quit_peer_threads_iterator(fake_peer, 0, fake_peer);
}

void prepare_exit_sp_mode(void)
{
	accept_conn = false;
	quit_all_peers();
	quit_fake_peer_info_thread();
	slog_info(FILE_LEVEL, "Removing the sp from the server");
	rm_sp_from_server();
	slog_info(FILE_LEVEL, "Extiting the sp network");
	exit_sp_network();
	slog_info(FILE_LEVEL, "Removing the sp_sock from the main poll");
	rm_poll_sp_sock();
}

void exit_sp_mode(void)
{
	slog_info(FILE_LEVEL, "Exiting the sp mode...");
	slog_info(FILE_LEVEL, "Closing the keys_cache");
	close_keys_cache();
	slog_info(FILE_LEVEL, "Destroying the known_peers list");
	list_destroy(known_peers);
	known_peers = NULL;
	fake_peer = NULL;
	slog_info(STDOUT_LEVEL, "You're no longer a superpeer");
}

#undef SP_BACKLOG