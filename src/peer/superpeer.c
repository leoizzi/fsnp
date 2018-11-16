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
#include "peer/superpeer.h"
#include "peer/port.h"
#include "peer/keys_cache.h"
#include "peer/thread_manager.h"
#include "peer/peer-superpeer.h"
#include "peer/superpeer-peer.h"
#include "peer/superpeer-superpeer.h"
#include "peer/stdin.h"

#include "fsnp/fsnp.h"

#include "struct/linklist.h"

#include "slog/slog.h"

#define SP_BACKLOG 128
#define MAX_KNOWN_PEER 8

#define READ_END 0
#define WRITE_END 1

//TODO: improve the error handling in the sockets' poll handlers

// TODO: add all the files of file_manager to the keys_cache when the peer is becoming a superpeer

/*
 * This list doesn't have a free callback because it shares the content with
 * a 'sp_tcp_thread'. The thread will free the memory when it's about to close
 */
static linked_list_t *known_peers = NULL;

/*
 * Contact the server used by the peer to join the P2P network for ask to add
 * this superpeer to its list.
 * Return 0 on success, -1 otherwise
 */
static int add_sp_to_server(void)
{
	int sock;
	struct fsnp_peer server_addr;
	struct in_addr ip;
	struct fsnp_add_sp add_sp;
	fsnp_err_t err;
	in_port_t sp_port;
	in_port_t p_port;

	get_server_addr(&server_addr);
	if (server_addr.ip == 0 && server_addr.port == 0) {
		// if the peer doesn't know any server how is possible that we are here?
		slog_panic(FILE_LEVEL, "The peer doesn't know a server, yet it's "
						 "becoming an sp");
		return -1;
	}

	ip.s_addr = server_addr.ip;
	slog_info(FILE_LEVEL, "Connecting with the server");
	sock = fsnp_create_connect_tcp_sock(ip, server_addr.port);
	if (sock < 0) {
		slog_error(FILE_LEVEL, "Unable to contact the server");
		return -1;
	}

	sp_port = get_udp_sp_port();
	p_port = get_tcp_sp_port();
	fsnp_init_add_sp(&add_sp, p_port, sp_port);
	slog_info(FILE_LEVEL, "Sending an add_sp msg with 'sp port: %hu', 'peer "
					   "port: %hu'", sp_port, p_port);
	err = fsnp_send_add_sp(sock, &add_sp);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
		close(sock);
		return -1;
	}

	close(sock);
	return 0;
}

/*
 * Create the superpeer's sockets and enter the overlay network
 */
static bool initialize_sp(struct fsnp_peer *sps, unsigned n)
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

	ret = add_sp_to_server();
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

	add_poll_sp_sock(tcp);
	return true;
}

/*
 * Check if a peer is already known
 */
static int peer_already_known(void *item, size_t idx, void *user)
{
	struct peer_info *peer = (struct peer_info *)item;
	struct sockaddr_in *addr = (struct sockaddr_in *)user;

	UNUSED(idx);

	if (peer->addr.ip == addr->sin_addr.s_addr) {
		if (peer->addr.port == addr->sin_port) {
			return STOP;
		}
	}

	return GO_AHEAD;
}

static void promote_peer(void)
{
	int msg = PIPE_PROMOTE;
	ssize_t w = 0;
	struct peer_info *to_promote = NULL;
	struct in_addr a;

	to_promote = list_shift_value(known_peers);
	a.s_addr = htonl(to_promote->addr.ip);
	slog_info(FILE_LEVEL, "Promoting peer %s:%hu", inet_ntoa(a), to_promote->addr.port);
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
	size_t n = 0;
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
	num_peers = list_count(known_peers);
	n = (size_t)list_foreach_value(known_peers, peer_already_known, &addr);
	if (num_peers != n) { // the peer is already known, don't accept it // TODO: this mechanism is broken: what if the peer already known is the last one?
		slog_warn(FILE_LEVEL, "Sp contacted by an already known peer");
		close(peer_sock);
		return;
	}

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

	if (num_peers + 1 > MAX_KNOWN_PEER) {
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

bool enter_sp_mode(struct fsnp_peer *sps, unsigned n)
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
	ret = initialize_sp(sps, n);
	if (!ret) {
		close_keys_cache();
		list_destroy(known_peers);
		printf("%s\n", err_msg);
		PRINT_PEER;
		return false;
	}

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
 * Remove this superpeer from the server's list
 */
static void rm_sp_from_server(void)
{
	int sock;
	struct fsnp_peer server_addr;
	struct fsnp_peer sp_addr;
	struct in_addr ip;
	struct fsnp_rm_sp rm_sp;
	fsnp_err_t err;

	get_server_addr(&server_addr);
	if (server_addr.ip == 0 && server_addr.port == 0) {
		// if the peer doesn't know any server how is possible that we are here?
		slog_panic(FILE_LEVEL, "The peer doesn't know a peer, yet it's becoming"
		                       " an sp");
		return;
	}

	ip.s_addr = server_addr.ip;
	slog_info(FILE_LEVEL, "Connecting with the server");
	sock = fsnp_create_connect_tcp_sock(ip, server_addr.port);
	if (sock < 0) {
		return;
	}

	sp_addr.ip = get_peer_ip();
	sp_addr.port = get_udp_sp_port();
	slog_info(FILE_LEVEL, "Sending a rm_sp msg to the server");
	fsnp_init_rm_sp(&rm_sp, &sp_addr, SUPERPEER);
	err = fsnp_send_rm_sp(sock, &rm_sp);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
		close(sock);
		return;
	}

	close(sock);
}

void prepare_exit_sp_mode(void)
{
	accept_conn = false;
	quit_all_peers();
	slog_info(FILE_LEVEL, "Removing the sp from the server");
	rm_sp_from_server();
}

void exit_sp_mode(void)
{
	slog_info(FILE_LEVEL, "Exiting the sp mode...");
	slog_info(FILE_LEVEL, "Extiting the sp network");
	exit_sp_network();
	slog_info(FILE_LEVEL, "Closing the keys_cache");
	close_keys_cache();
	slog_info(FILE_LEVEL, "Removing the sp_sock from the main poll");
	rm_poll_sp_sock();
	slog_info(FILE_LEVEL, "Destroying the known_peers list");
	list_destroy(known_peers);
	known_peers = NULL;
	slog_info(STDOUT_LEVEL, "You're no longer a superpeer");
}

#undef READ_END
#undef WRITE_END
#undef SP_BACKLOG
#undef MAX_KNOWN_PEER