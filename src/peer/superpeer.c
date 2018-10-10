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

#include "peer/peer.h"
#include "peer/superpeer.h"
#include "peer/port.h"
#include "peer/file_cache.h"
#include "peer/thread_manager.h"
#include "peer/peer-superpeer.h"
#include "peer/superpeer-peer.h"
#include "peer/superpeer-superpeer.h"

#include "fsnp/fsnp.h"

#include "struct/linklist.h"

#define SP_BACKLOG 128
#define MAX_KNOWN_PEER 8

#define READ_END 0
#define WRITE_END 1

//TODO: improve the error handling in the sockets' poll handlers

/*
 * This list doesn't have a free callback because it shares the content with
 * a 'sp_tcp_thread'. The thread will free the memory when it's about to close
 */
static linked_list_t *known_peers = NULL;

/*
 * Create the superpeer's sockets and enter the overlay network
 */
static bool initialize_sp(void)
{
	int udp = 0;
	int tcp = 0;
	int ret = 0;
	in_port_t udp_port = SP_UDP_PORT;
	in_port_t tcp_port = SP_TCP_PORT;
	bool localhost = is_localhost();

	tcp = fsnp_create_bind_tcp_sock(&tcp_port, localhost);
	if (tcp < 0) {
		return false;
	}

	udp = fsnp_create_bind_udp_sock(&udp_port, localhost);
	if (udp < 0) {
		close(tcp);
		return false;
	}

#ifdef FSNP_DEBUG
bool print_peer = false;

	if (tcp != SP_TCP_PORT) {
		fprintf(stderr, "Unable to bind the superpeer TCP socket to the port"
		                " %hu. The port %hu has been used instead\n",
		        (in_port_t)SP_TCP_PORT, tcp_port);
		print_peer = true;
	}

	if (udp_port != SP_UDP_PORT) {
		fprintf(stderr, "Unable to bind the superpeer UDP socket to the port"
		                " %hu. The port %hu has been used instead\n",
		        (in_port_t)SP_UDP_PORT, udp_port);
		print_peer = true;
	}

	if (print_peer) {
		PRINT_PEER;
	}
#endif

	ret = listen(tcp, SP_BACKLOG);
	if (ret < 0) {
		fprintf(stderr, "Unable to listen on the TCP port.\n");
		close(tcp);
		close(udp);
		PRINT_PEER;
		return false;
	}

	if (get_peer_sock() != 0) {
		// We're getting promoted, leave the superpeer before going forward
		leave_sp();
	}

	// TODO: add this superpeer to the server list

	ret = enter_sp_network(udp);
	if (ret < 0) {
		fprintf(stderr, "Unable to enter the superpeer network\n");
		close(tcp);
		close(udp);
		PRINT_PEER;
		return false;
	}

	add_poll_sp_sock(tcp);
	set_udp_sp_port(udp_port);
	set_tcp_sp_port(tcp_port);
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

	to_promote = list_shift_value(known_peers);
	w = fsnp_write(to_promote->pipefd[WRITE_END], &msg, sizeof(int));
	if (w < 0) {
		perror("Unable to promote a peer");
	}
}

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


	s = get_tcp_sp_port();

	peer_sock = accept(s, (struct sockaddr *)&addr, &socklen);
	if (peer_sock < 0) {
		perror("Unable to accept a new TCP connection");
		PRINT_PEER;
		return;
	}

	addr.sin_addr.s_addr = ntohl(addr.sin_addr.s_addr);
	addr.sin_port = ntohs(addr.sin_port);
	num_peers = list_count(known_peers);
	n = (size_t)list_foreach_value(known_peers, peer_already_known, &addr);
	if (num_peers != n) { // the peer is already known, don't accept it
		close(peer_sock);
		return;
	}

	peer_info = malloc(sizeof(struct peer_info));
	if (!peer_info) {
		close(peer_sock);
		perror("Unable to allocate enough memory");
		PRINT_PEER;
		return;
	}

	peer_info->addr.ip = ntohl(addr.sin_addr.s_addr);
	peer_info->addr.port = ntohs(addr.sin_port);
	peer_info->sock = peer_sock;
	ret = pipe(peer_info->pipefd);
	if (ret < 0) {
		perror("accept_peer-pipe");
		close(peer_sock);
		free(peer_info);
		PRINT_PEER;
	}

	added = list_push_value(known_peers, peer_info);
	if (ret < 0) {
		fprintf(stderr, "Unable to add the peer to the known_peer_list\n");
		PRINT_PEER;
	}

	ret = start_new_thread(sp_tcp_thread, peer_info, "sp_tcp_thread");
	if (ret < 0) {
		fprintf(stderr, "Unable to start 'sp_tcp_thread' for peer %s:%hu\n",
				inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
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

/*
 * Read a message on the UDP socket
 */
static void read_udp_sock(void)
{
	// TODO: continue sp UDP comm
}

void sp_tcp_sock_event(short revents)
{
	if (revents & POLLIN || revents & POLLRDBAND || revents & POLLPRI) {
		accept_peer();
	} else {
#ifdef FSNP_DEBUG
		fprintf(stderr, "sp TCP socket. Case not covered!\n");
		printf("revents: %hd\n", revents);
		PRINT_PEER;
#endif
	}
}

void sp_udp_sock_event(short revents)
{
	if (revents & POLLIN || revents & POLLRDBAND || revents & POLLPRI) {
		read_udp_sock();
	} else {
#ifdef FSNP_DEBUG
		fprintf(stderr, "sp UDP socket. Case not covered!\n");
		printf("revents: %hd\n", revents);
		PRINT_PEER;
#endif
	}
}

bool enter_sp_mode(void)
{
	bool ret = false;

	ret = init_file_cache();
	if (!ret) {
		return false;
	}

	known_peers = list_create();
	if (!known_peers) {
		close_file_cache();
		return false;
	}

	ret = initialize_sp();
	if (!ret) {
		close_file_cache();
		return false;
	}

	return true;
}

/*
 * For each thread spawned for communicating with a peer tell it to quit
 */
static int quit_peer_threads(void *item, size_t idx, void *user)
{
	struct peer_info *info = (struct peer_info *)item;
	struct in_addr addr;
	ssize_t w = 0;
	int msg = PIPE_QUIT;

	UNUSED(idx);
	UNUSED(user);

	w = fsnp_write(info->pipefd[WRITE_END], &msg, sizeof(int));
	if (w < 0) {
		addr.s_addr = htonl(info->addr.ip);
		fprintf(stderr, "Unable to communicate to the 'sp_tcp_thread' of peer"
				  "%s:%hu to quit\n", inet_ntoa(addr), htons(info->addr.port));
		PRINT_PEER;
	}
}

void exit_sp_mode(void)
{
	exit_sp_network();
	close_file_cache();
	list_foreach_value(known_peers, quit_peer_threads, NULL);
	rm_poll_sp_sock();
	list_destroy(known_peers);
	known_peers = NULL;
}

#undef READ_END
#undef WRITE_END
#undef SP_BACKLOG
#undef MAX_KNOWN_PEER