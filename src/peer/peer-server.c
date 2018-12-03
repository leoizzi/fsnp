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
#include <errno.h>

#include "peer/peer.h"
#include "peer/superpeer.h"
#include "peer/peer-server.h"
#include "peer/peer-superpeer.h"
#include "peer/thread_manager.h"
#include "peer/stdin.h"

#include "fsnp/fsnp.h"

#include "slog/slog.h"

/*
 * Send a fsnp_query message to the server
 */
static bool send_query(int sock)
{
	struct fsnp_query query;
	fsnp_err_t err;

	fsnp_init_query(&query, PEER);
	slog_debug(FILE_LEVEL, "Sending query msg to the server");
	err = fsnp_send_query(sock, &query);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
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

	slog_debug(FILE_LEVEL, "Reading query_res sent by the server");
	msg = fsnp_read_msg_tcp(sock, 0, &t, &err);
	if (!msg) {
		fsnp_log_err_msg(err, false);
		return NULL;
	}

	if (msg->msg_type != QUERY_RES) {
		slog_debug(FILE_LEVEL, "msg_type mismatch: expected %u, received %u",
				QUERY_RES, msg->msg_type);
		free(msg);
		return NULL;
	}

	query_res = (struct fsnp_query_res *)msg;
	return query_res;
}

/*
 * Add the peer to the server superpeer list
 */
static void first_peer(void)
{
	struct fsnp_add_sp add_sp;
	struct fsnp_peer server;
	struct in_addr ip;
	fsnp_err_t err;
	bool ret = false;
	int sock = 0;

	slog_debug(FILE_LEVEL, "This peer is the first to join the network");
	if (is_superpeer()) { // something really wrong happened with the server
		slog_warn(FILE_LEVEL, "This peer is already a superpeer and the server"
				  " doesn't know about it. Sending a request to add us to its "
	              "list");
		get_server_addr(&server);
		ip.s_addr = server.ip;
		sock = fsnp_create_connect_tcp_sock(ip, server.port);
		if (sock < 0) {
			slog_error(FILE_LEVEL, "fsnp_create_connect_tcp_sock error %d", errno);
			return;
		}

		fsnp_init_add_sp(&add_sp, get_tcp_sp_port(), get_udp_sp_port());
		err = fsnp_send_add_sp(sock, &add_sp);
		if (err != E_NOERR) {
			fsnp_log_err_msg(err, false);
			close(sock);
			return;
		}

		close(sock);
	} else {
		ret = enter_sp_mode(NULL, NO_SP);
		if (ret == false) {
			slog_error(STDOUT_LEVEL, "Unable to enter the sp_mode");
			PRINT_PEER;
			return;
		}
	}

	slog_info(STDOUT_LEVEL, "You're the first peer in the network!");
	PRINT_PEER;
}

/*
 * Parse the server response, checking if the peer is the first one to contact
 * the server or not
 */
static void parse_query_res(struct fsnp_query_res *query_res)
{
	set_peer_ip(query_res->peer_addr);
	if (query_res->num_sp == 1) {
		if (query_res->sp_list[0].ip == 0 && query_res->sp_list[0].port == 0) {
			first_peer();
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
	struct fsnp_peer server_addr;
	char err_msg[] = "An error has occurred while contacting the superpeer. See"
				     " the log for more details";

	sock = fsnp_create_connect_tcp_sock(addr->sin_addr, addr->sin_port);
	if (sock < 0) {
		slog_error(FILE_LEVEL, "fsnp_create_connect_tcp_sock error: %d", errno);
		printf("%s\n", err_msg);
		PRINT_PEER;
		return;
	}

	if (!send_query(sock)) {
		printf("%s\n", err_msg);
		PRINT_PEER;
		return;
	}

	query_res = read_res(sock);
	if (!query_res) {
		printf("%s\n", err_msg);
		PRINT_PEER;
		return;
	}

	close(sock);
	server_addr.ip = addr->sin_addr.s_addr;
	server_addr.port = addr->sin_port;
	set_server_addr(&server_addr);

	parse_query_res(query_res);

	free(query_res);
}

int add_sp_to_server(void)
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

void rm_sp_from_server(void)
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

void rm_dead_sp_from_server(struct fsnp_peer *dead_sp)
{
	int sock = 0;
	struct fsnp_peer serv;
	struct in_addr addr;
	struct fsnp_rm_sp rm_sp;
	fsnp_err_t err;

	get_server_addr(&serv);
	addr.s_addr = htonl(serv.ip);
	sock = fsnp_create_connect_tcp_sock(addr, serv.port);
	if (sock < 0) {
		slog_error(FILE_LEVEL, "Unable to establish a connection with the server");
		return;
	}

	fsnp_init_rm_sp(&rm_sp, dead_sp, SUPERPEER);
	err = fsnp_send_rm_sp(sock, &rm_sp);
	if (err != E_NOERR) {
		close(sock);
		fsnp_log_err_msg(err, false);
		return;
	}

	close(sock);
}

void launch_query_server_sp(const struct sockaddr_in *addr)
{
	struct sockaddr_in *addr_cp = NULL;

	addr_cp = malloc(sizeof(struct sockaddr_in));
	if (!addr_cp) {
		slog_error(FILE_LEVEL, "malloc. Error %d", errno);
		printf("An internal error has occurred while contacting the server\n");
		PRINT_PEER;
		return;
	}

	memcpy(addr_cp, addr, sizeof(struct sockaddr_in));
	start_new_thread(query_server, addr_cp, "query_server");
}