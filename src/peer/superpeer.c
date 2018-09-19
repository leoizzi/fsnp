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
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>

#include "peer/peer.h"
#include "peer/superpeer.h"
#include "peer/port.h"
#include "peer/file_cache.h"
#include "peer/thread_manager.h"
#include "peer/superpeer-peer.h"
#include "peer/superpeer-superpeer.h"

#include "fsnp/fsnp.h"

#include "struct/linklist.h"

#define SP_BACKLOG 128
#define MAX_KNOWN_PEER 8

/*
 * This list doesn't have a free callback because it shares the content with
 * a 'peer_thread'. The thread will free the memory when it's about to close
 */
static linked_list_t *known_peers = NULL;

static bool create_sp_socks(void)
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

	if (tcp != SP_TCP_PORT) {
		fprintf(stderr, "Unable to bind the superpeer TCP socket to the port"
		                " %hu. The port %hu has been used instead\n",
		        (in_port_t)SP_TCP_PORT, tcp_port);
	}

	if (udp_port != SP_UDP_PORT) {
		fprintf(stderr, "Unable to bind the superpeer UDP socket to the port"
		                " %hu. The port %hu has been used instead\n",
		        (in_port_t)SP_UDP_PORT, udp_port);
	}

	ret = listen(tcp, SP_BACKLOG);
	if (ret < 0) {
		fprintf(stderr, "Unable to listen on the TCP port.\n");
		close(tcp);
		close(udp);
		return false;
	}

	ret = enter_sp_network(udp);
	if (ret < 0) {
		fprintf(stderr, "Unable to enter the superpeer network\n");
		close(tcp);
		close(udp);
		return false;
	}

	rm_peer_sock();
	add_poll_sp_sock(tcp);
	set_udp_sp_port(udp_port);
	set_tcp_sp_port(tcp_port);
	return true;
}

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

/*
 * Accept a new peer, establishing a TCP connection with him. Then add
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


	s = get_tcp_sp_port();

	peer_sock = accept(s, (struct sockaddr *)&addr, &socklen);
	if (peer_sock < 0) {
		perror("Unable to accept a new TCP connection");
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
		return;
	}

	peer_info->addr.ip = addr.sin_addr.s_addr;
	peer_info->addr.port = addr.sin_port;
	peer_info->sock = peer_sock;
	ret = start_new_thread(peer_thread, peer_info, NULL);
	if (ret < 0) {
		close(peer_sock);
		free(peer_info);
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
	if (revents & POLLERR) {
		printf("An exceptional error has occurred on the sp TCP socket.\n");
	} else if (revents & POLLIN || revents & POLLRDBAND || revents & POLLPRI) {
		accept_peer();
	} else {
#ifdef FSNP_DEBUG
		fprintf(stderr, "sp TCP socket. Case not covered!\n");
		printf("revents: %hd\n", revents);
#endif
	}
}

void sp_udp_sock_event(short revents)
{
	if (revents & POLLERR) {
		printf("An exceptional error has occurred on the sp UDP socket.\n");
	} else if (revents & POLLIN || revents & POLLRDBAND || revents & POLLPRI) {
		read_udp_sock();
	} else {
#ifdef FSNP_DEBUG
		fprintf(stderr, "sp UDP socket. Case not covered!\n");
		printf("revents: %hd\n", revents);
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

	ret = create_sp_socks();
	if (!ret) {
		close_file_cache();
		return false;
	}

	return true;
}

void exit_sp_mode(void)
{
	exit_sp_network();
	close_file_cache();
	// TODO: if there are threads communicating with peers join them before going on
	rm_poll_sp_sock();
	list_destroy(known_peers);
	known_peers = NULL;
}