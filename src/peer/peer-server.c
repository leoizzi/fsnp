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
#include <stdbool.h>
#include <unistd.h>
#include <memory.h>
#include <arpa/inet.h>

#include "peer/peer.h"
#include "peer/superpeer.h"
#include "peer/peer-server.h"
#include "peer/peer-superpeer.h"
#include "peer/thread_manager.h"
#include "peer/stdin.h"

#include "fsnp/fsnp.h"

/*
 * Send a fsnp_query message to the server
 */
static bool send_query(int sock)
{
	struct fsnp_query query;
	fsnp_err_t err;

	fsnp_init_query(&query, PEER);
	err = fsnp_send_query(sock, &query);
	if (err != E_NOERR) {
		fsnp_print_err_msg(err);
		return false;
	}

	return true;
}

/*
 * Read the fsnp_query_res sent by the server
 */
static struct fsnp_query_res *read_res(int sock)
{
	fsnp_err_t err;
	ssize_t t = 0;
	struct fsnp_msg *msg = NULL;
	struct fsnp_query_res *query_res = NULL;

	msg = fsnp_read_msg_tcp(sock, 0, &t, &err);
	if (!msg) {
		fsnp_print_err_msg(err);
		return NULL;
	}

	query_res = (struct fsnp_query_res *)msg;
	return query_res;
}

/*
 * Add the peer to the server superpeer list
 */
static void first_peer(int sock)
{
	struct fsnp_add_sp add_sp;
	fsnp_err_t err;
	bool ret = false;

	if (is_superpeer()) { // something really wrong happened with the server
		fprintf(stderr, "This program is already a superpeer and the server"
				  " doesn't know about it.\nSending a request to add this"
	              " superpeer to its list\n");
		fsnp_init_add_sp(&add_sp, get_tcp_sp_port(), get_udp_sp_port());
		err = fsnp_send_add_sp(sock, &add_sp);
		if (err != E_NOERR) {
			fsnp_print_err_msg(err);
			PRINT_PEER;
			return;
		}
	} else {
		ret = enter_sp_mode();
		if (ret == false) {
			perror("enter_sp_mode-first_peer");
			PRINT_PEER;
			return;
		}
	}

	printf("\nYou're the first peer in the network!\n");
	PRINT_PEER;
}

/*
 * Parse the server response, checking if the peer is the first one to contact
 * the server or not
 */
static void parse_query_res(int sock, struct fsnp_query_res *query_res)
{
	if (query_res->num_sp == 1) {
		if (query_res->sp_list[0].ip == 0 && query_res->sp_list[0].port == 0) {
			first_peer(sock);
			return;
		}
	}

	join_sp(query_res);
}

/*
 * Entry point for the thread that will communicate with the server
 */
static void query_server(void *data)
{
	int sock = 0;
	struct sockaddr_in *addr = (struct sockaddr_in *)data;
	struct fsnp_query_res *query_res = NULL;

	sock = fsnp_create_connect_tcp_sock(addr->sin_addr, addr->sin_port);
	if (sock < 0) {
		perror("fsnp_create_connect_tcp_sock peer-server");
		return;
	}

	if (!send_query(sock)) {
		return;
	}

	query_res = read_res(sock);
	if (!query_res) {
		return;
	}

	parse_query_res(sock, query_res);

	close(sock);
	free(query_res);
}

void launch_query_server_sp(const struct sockaddr_in *addr)
{
	struct sockaddr_in *addr_cp = NULL;

	addr_cp = malloc(sizeof(struct sockaddr_in));
	if (!addr_cp) {
		perror("launch_query_server_sp-malloc");
		return;
	}

	memcpy(addr_cp, addr, sizeof(struct sockaddr_in));
	start_new_thread(query_server, addr_cp, "query_server");
}