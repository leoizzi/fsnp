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

 /*
  * HOW TO RUN
  *
  * start the boot_server executable, then launch this.
  */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <memory.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>

#include "fsnp/fsnp.h"

static int s = 0; // socket

static void open_conn(void)
{
	struct sockaddr_in sockaddr;
	socklen_t socklen = 0;
	int ret = 0;

	s = socket(PF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror("socket");
	}

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sockaddr.sin_port = htons(38818);
	sockaddr.sin_family = AF_INET;
	socklen = sizeof(sockaddr);
	ret = connect(s, (struct sockaddr *)&sockaddr, socklen);
	if (ret < 0) {
		perror("connect");
		close(s);
		exit(EXIT_FAILURE);
	}
}

static in_port_t p_port; // peer port
static in_port_t sp_port; // sp_port

static void inline gen_rand_sp(void)
{
	p_port = (in_port_t)(rand() % UINT16_MAX);
	sp_port = (in_port_t)(rand() % UINT16_MAX);
}

static void add_peer(void)
{
	struct fsnp_add_sp add_sp;
	fsnp_err_t err;
	ssize_t w = 0;

	gen_rand_sp();
	fsnp_init_add_sp(&add_sp, p_port, sp_port);
	w = fsnp_write_msg_tcp(s, 0, (const struct fsnp_msg *)&add_sp, &err);
	if (w < 0) {
		fsnp_log_err_msg(err, NULL);
		close(s);
		exit(EXIT_FAILURE);
	}

	printf("Bytes written: %lu\n\n", w);
	printf("Superpeer sent: p_port: %hu, sp_port: %hu\n", p_port, sp_port);
	close(s);
}

static void rm_peer(void)
{
	struct fsnp_peer p;
	struct fsnp_rm_sp rm;
	ssize_t w = 0;
	fsnp_err_t err;

	p.ip = INADDR_LOOPBACK; // No need to swap on a little endian machine
	p.port = p_port;
	fsnp_init_rm_sp(&rm, &p, PEER);
	w = fsnp_write_msg_tcp(s, 0, (const struct fsnp_msg *)&rm, &err);
	if (w < 0) {
		fsnp_log_err_msg(err, NULL);
		close(s);
		exit(EXIT_FAILURE);
	}
}

static void query(int i)
{
	fsnp_peer_type_t type;
	struct fsnp_query query;
	ssize_t w = 0;
	fsnp_err_t err;

	if (i % 4 == 0) {
		type = PEER;
		printf("Asking for the peer port\n");
	} else {
		type = SUPERPEER;
		printf("Asking for the superpeer port\n");
	}

	fsnp_init_query(&query, type);
	w = fsnp_write_msg_tcp(s, 0, (const struct fsnp_msg *)&query, &err);
	if (w < 0) {
		fsnp_log_err_msg(err, NULL);
		close(s);
		exit(EXIT_FAILURE);
	}
}

static void query_res(void)
{
	struct fsnp_query_res *query_res = NULL;
	struct fsnp_msg *msg = NULL;
	struct in_addr addr;
	fsnp_err_t err;
	ssize_t r = 0;
	int j = 0;

	msg = fsnp_read_msg_tcp(s, 0, &r, &err);
	if (!msg) {
		fsnp_log_err_msg(err, NULL);
		close(s);
		exit(EXIT_FAILURE);
	}

	printf("Bytes read: %ld\n", r);
	if (msg->msg_type != QUERY_RES) {
		fprintf(stderr, "Unexpected msg type\n");
		close(s);
		exit(EXIT_FAILURE);
	}

	query_res = (struct fsnp_query_res *)msg;
	addr.s_addr = htonl(query_res->peer_addr);
	printf("IP used by this executable: %s\n", inet_ntoa(addr));

	if (query_res->num_sp == 1) {
		if (query_res->sp_list->ip == 0 && query_res->sp_list->port == 0) {
			printf("The server doesn't know any peer. Registering as superpeer\n");
			return;
		}
	}

	for (j = 0; j < query_res->num_sp; j++) {
		addr.s_addr = htonl(query_res->sp_list[j].ip); // swap to big endian for printing
		printf("Peer %d\tAddress: %s\tPort: %hu\n", j, inet_ntoa(addr),
		       query_res->sp_list[j].port);
	}

	free(query_res);
}

 int main(int argc, char **argv)
{
 	int i = 0;

 	UNUSED(argv);

 	if (argc > 1) {
 		fprintf(stderr, "Do not pass arguments.\n");
 		exit(EXIT_FAILURE);
 	}

 	srand((unsigned)time(NULL));

 	// first peer test
 	printf("\n\nfirst_peer test\n");
	open_conn();
	query(0);
	query_res();
	add_peer();
	close(s);

	// add peer test
 	printf("\n\nadd_sp test\n");
 	for (i = 0; i < 20; i++) {
 		open_conn();
 		add_peer();
 		close(s);
    }

    // query test
    for (i = 0; i < 10; i++) {
    	printf("\n\nQuery test n. %d\n", i);
    	open_conn();
    	query(i);
    	query_res();
	    close(s);
    }

    // rm_sp

    printf("\n\nrm_sp test\n");
    printf("Adding the superpeer to be removed\n");
	open_conn();
	add_peer();
	close(s);

	printf("Going to sleep...\n");
	// sleep 5 seconds, so that we're sure the superpeer was added
	sleep(5);

	printf("Removing the superpeer previously added\n");
	open_conn();
	rm_peer();
	close(s);

	return EXIT_SUCCESS;
}
