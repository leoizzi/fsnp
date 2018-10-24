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
#include <stdint.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <memory.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#include "fsnp/fsnp.h"
#include "boot_server/server_sock.h"
#include "boot_server/sp_manager.h"

#include "slog/slog.h"

struct handler_data {
	int sock;
	struct sockaddr_in addr;
};

/*
 * NOTE: in the add_sp_msg and the rm_sp_msg locks aren't used because the struct
 * library uses them internally
 */

/*
 * Add who contact the server to the superpeer's list
 */
static void add_sp_msg(const struct handler_data *data,
					   const struct fsnp_add_sp *msg)
{
	struct fsnp_server_sp *fsp = NULL;
	int ret = 0;

#ifdef FSNP_DEBUG
	struct in_addr address; // for printing purposes only
#endif

	fsp = malloc(sizeof(struct fsnp_server_sp));
	if (!fsp) {
		slog_error(FILE_LEVEL, "malloc. Error :%d", errno);
		return;
	}

	fsp->addr.s_addr = ntohl(data->addr.sin_addr.s_addr);
	fsp->p_port = msg->p_port;
	fsp->sp_port = msg->sp_port;
	ret = add_sp_to_list(fsp);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Unable to add the sp %s with p_port = %hu and"
						 " sp_port = %hu to the list",
						 inet_ntoa(data->addr.sin_addr), fsp->p_port,
						 fsp->sp_port);
		free(fsp);
	}

#ifdef FSNP_DEBUG
	address.s_addr = htonl(fsp->addr.s_addr);
	slog_debug(FILE_LEVEL, "Superpeer added: address: %s, p_port: %hu, sp_port:"
						" %hu", inet_ntoa(address), fsp->p_port, fsp->sp_port);
#endif
}

/*
 * Remove the given superpeer from the superpeer's list
 */
static void rm_sp_msg(const struct handler_data *data,
					  const struct fsnp_rm_sp *msg)
{
	struct fsnp_peer p;
	struct fsnp_server_sp *sp = NULL;

	UNUSED(data);

	p.ip = msg->addr.ip;
	p.port = msg->addr.port;
	sp = rm_sp(&p, msg->peer_type);
	if (sp) {
#ifdef FSNP_DEBUG
		struct in_addr addr;
		addr.s_addr = htonl(sp->addr.s_addr);
		slog_debug(FILE_LEVEL, "Removed superpeer with address %s, p_port %hu,"
						 " sp_port %hu", inet_ntoa(addr), sp->p_port,
						 sp->sp_port);
#endif
		free(sp);
	}
}

/*
 * Called by query_msg when the server know at least one superpeer
 */
static void normal_query_res(const struct handler_data *data,
							 const struct fsnp_query *msg)
{
	uint8_t num_sp = 0;
	struct fsnp_peer *sp = NULL;
	struct fsnp_query_res *query_res = NULL;
	fsnp_err_t err;

	sp = read_sp_by_type(&num_sp, msg->peer_type);
	if (!sp) {
		slog_error(FILE_LEVEL, "Unable to read the sp from the sp manager");
		return;
	}

	query_res = fsnp_create_query_res(ntohl(data->addr.sin_addr.s_addr), num_sp,
									  sp);
	if (!query_res) {
		slog_error(FILE_LEVEL, "Unable to create the query_res");
		return;
	}

	free(sp);
	slog_debug(FILE_LEVEL, "Sending a filled query_res to %s:hu",
			inet_ntoa(data->addr.sin_addr), ntohs(data->addr.sin_port));
	err = fsnp_send_query_res(data->sock, query_res);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
	}

#ifdef FSNP_DEBUG
	static uint64_t counter = 0;
	slog_debug(FILE_LEVEL, "Query response n. %llu sent to peer %s:%hu\n",
			counter, inet_ntoa(data->addr.sin_addr), ntohs(data->addr.sin_port));
	counter++;
#endif

	free(query_res);
}

/*
 * Called by query_msg when the server doesn't know any superpeer
 */
static void first_query_res(const struct handler_data *data,
							const struct fsnp_query *msg)
{
	struct fsnp_query_res *query_res = NULL;
	struct fsnp_msg *m = NULL;
	ssize_t r = 0;
	fsnp_err_t err;

	UNUSED(msg);

	query_res = fsnp_create_query_res(ntohl(data->addr.sin_addr.s_addr), 0,
									  NULL);
	if (!query_res) {
		slog_error(FILE_LEVEL, "fsnp_create_query_res. Error: %d", errno);
		return;
	}

	slog_debug(FILE_LEVEL, "Sending an empty query_res to %s:%hu",
			   inet_ntoa(data->addr.sin_addr), ntohs(data->addr.sin_port));
	err = fsnp_send_query_res(data->sock, query_res);
	if (err != E_NOERR && err != E_PEER_DISCONNECTED) {
		fsnp_log_err_msg(err, false);
		return;
	} else if (err == E_PEER_DISCONNECTED) {
		// the peer has closed the connection
		slog_info(FILE_LEVEL, "The peer has terminated the connection");
		return;
	}

	free(query_res);
	slog_debug(FILE_LEVEL, "Reading the answer from peer %s:%hu",
			   inet_ntoa(data->addr.sin_addr), ntohs(data->addr.sin_port));
	m = fsnp_read_msg_tcp(data->sock, 0, &r, &err);
	if (!m) {
		if (r < 0) {
			fsnp_log_err_msg(err, false);
		}

		return;
	}

	if (m->msg_type != ADD_SP) {
		slog_info(FILE_LEVEL, "Unexpected msg_type: %u, the server was waiting for: %u."
			" Closing the communication with %s:%hu", m->msg_type, ADD_SP,
			inet_ntoa(data->addr.sin_addr), ntohs(data->addr.sin_port));
		return;
	}

	slog_info(FILE_LEVEL, "%s:hu is the first peer in the network",
			inet_ntoa(data->addr.sin_addr), ntohs(data->addr.sin_port));
	add_sp_msg(data, (struct fsnp_add_sp *)m);
	free(m);
}

/*
 * Respond to the query message, sending back to the peer the list of known peers
 */
static void query_msg(const struct handler_data *data,
                      const struct fsnp_query *msg)
{
	if (msg->peer_type != PEER && msg->peer_type != SUPERPEER) {
		slog_debug(FILE_LEVEL, "fsnp_query_msg: unknown peer type");
		return;
	}

	lock_sp_list();

	if (count_sp() == 0) { // We're dealing with the first peer of the network
		slog_debug(FILE_LEVEL, "first_query_res is being called");
		first_query_res(data, msg);
		unlock_sp_list();
	} else {
		unlock_sp_list();
		slog_debug(FILE_LEVEL, "normal_query_res is being called");
		normal_query_res(data, msg);
	}
}

/*
 * Entry point for socket's threads.
 * Parse the request message and send the response
 */
static void *handler_thread(void *val)
{
	struct handler_data *data = (struct handler_data *)val;
	struct fsnp_msg *msg = NULL;
	fsnp_err_t err;

	msg = fsnp_read_msg_tcp(data->sock, 0, NULL, &err);
	if (!msg) {
		fsnp_log_err_msg(err, false);
		// goto used in order to avoid the boilerplate of conditional compilation
		goto server_handler_exit;
	}

	switch (msg->msg_type) {
		case QUERY:
			slog_debug(FILE_LEVEL, "QUERY message received");
			query_msg(data, (struct fsnp_query *)msg);
			break;

		case ADD_SP:
			slog_debug(FILE_LEVEL, "ADD_SP message received");
			add_sp_msg(data, (struct fsnp_add_sp *)msg);
			break;

		case RM_SP:
			slog_debug(FILE_LEVEL, "RM_SP message received");
			rm_sp_msg(data, (struct fsnp_rm_sp *)msg);
			break;

		default:
			slog_debug(FILE_LEVEL, "A message of an unexpected type has been"
						           " received");
			break;
	}

	free(msg);

server_handler_exit:
	slog_info(FILE_LEVEL, "Closing thread used for peer %s:hu",
	          inet_ntoa(data->addr.sin_addr), ntohs(data->addr.sin_port));
	close(data->sock);
	free(data);
#ifndef FSNP_MEM_DEBUG
	pthread_exit(NULL);
#else
	return NULL;
#endif
}

static void launch_handler_thread(int sock, const struct sockaddr_in *addr)
{
	int ret = 0;
	pthread_t tid;
	struct handler_data *data = NULL;

	data = malloc(sizeof(struct handler_data));
	if (!data) {
		slog_error(FILE_LEVEL, "malloc. Error: %d", errno)
		close(sock);
		return;
	}

	data->sock = sock;
	memcpy(&data->addr, addr, sizeof(*addr));
#ifndef FSNP_MEM_DEBUG
	ret = pthread_create(&tid, NULL, handler_thread, data);
	if (ret) {
		slog_error(FILE_LEVEL, "Unable to start the handler thread");
		close(sock);
		free(data);
	}

	ret = pthread_detach(tid);
	if (ret) {
		slog_warn(STDOUT_LEVEL, "Unable to detach a thread. (You may want to"
						        " reset the server if this happens again... "
			                    "Memory leaks are on their way!)");
	}

#else// ifdef FSNP_MEM_DEBUG
	slog_debug(FILE_LEVEL, "handler_thread called on main thread");
	handler_thread(data);
#endif
}

/*
 * Accept the incoming connection and launch the handler thread
 */
static void accept_conn(int main_sock)
{
	int sock = 0;
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	memset(&addr, 0, len);
	sock = accept(main_sock, (struct sockaddr *)&addr, &len);
	if (sock < 0) {
		slog_warn(FILE_LEVEL, "Error while accepting a new connection");
		return;
	}

	slog_info(FILE_LEVEL, "Server contacted by peer %s:hu",
			inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	launch_handler_thread(sock, &addr);
}

void server_socket_handler(int main_sock, short revents)
{
	if (revents & POLLERR || revents & POLLHUP || revents & POLLNVAL) {
		slog_warn(STDOUT_LEVEL, "An error has occurred on the main socket");
		slog_error(FILE_LEVEL, "revents: %hd", revents);
	} else if (revents & POLLIN || revents & POLLPRI || revents & POLLRDBAND) {
		accept_conn(main_sock);
	} else {
		slog_warn(FILE_LEVEL, "Unknown poll revent: %hd", revents);
	}
}
