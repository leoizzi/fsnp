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
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <limits.h>
#include <stdint.h>
#include <memory.h>

#include "fsnp/fsnp.h"

/*
 * HOW TO RUN
 *
 * start the boot_server first, then start this executable. After that launch
 * the peer. Set a shared_dir and join this "superpeer".
 * The join should happens automatically if this executable is the only superpeer
 * known by the server.
 */

static int sp_sock = 0;
static int peer_sock = 0;

static void connect_to_server(void)
{
	int s = 0;
	struct in_addr addr;
	struct fsnp_add_sp add_sp;
	in_port_t port = 38000;
	ssize_t w = 0;
	fsnp_err_t err;

	sp_sock = fsnp_create_bind_tcp_sock(&port, true);
	if (sp_sock < 0) {
		perror("connect_to_server - fsnp_create_bind_tcp_sock");
		exit(EXIT_FAILURE);
	}

	addr.s_addr = INADDR_LOOPBACK;
	s = fsnp_create_connect_tcp_sock(addr, 38818);
	if (s < 0) {
		perror("connect_to_server - fsnp_create_connect_tcp_sock");
		exit(EXIT_FAILURE);
	}

	fsnp_init_add_sp(&add_sp, port, 0); // the sp port doesn't matter with this test
	w = fsnp_write_msg_tcp(s, 0, (const struct fsnp_msg *)&add_sp, &err);
	if (w < 0) {
		fprintf(stderr, "Unable to send the add_sp message to the server\n");
		fsnp_log_err_msg(err, NULL);
		exit(EXIT_FAILURE);
	}
}

static void wait_for_peer(void)
{
	int ret = 0;
	struct sockaddr_in addr;
	socklen_t socklen = sizeof(addr);

	ret = listen(sp_sock, 128);
	if (ret < 0) {
		perror("listen - wait_for_peer");
		exit(EXIT_FAILURE);
	}

	peer_sock = accept(sp_sock, (struct sockaddr *)&addr, &socklen);
	if (peer_sock < 0) {
		perror("accept - wait_for_peer");
		exit(EXIT_FAILURE);
	}

	printf("Connection accepted with peer %s:%hu\n", inet_ntoa(addr.sin_addr),
			                                         ntohs(addr.sin_port));
}

static void join_received(struct fsnp_join *join)
{
	uint32_t i = 0;
	uint32_t j = 0;
	sha256_t key;
	struct fsnp_ack ack;
	ssize_t w = 0;
	fsnp_err_t err;

	printf("Join message received!\n");
	printf("%u keys received from the peer\n\n", join->num_files);
	for (i = 0; i < join->num_files; i++) {
		memcpy(key, join->files_hash + i * sizeof(sha256_t), sizeof(sha256_t));
		printf("%u: ", i);
		for (j = 0; j < sizeof(sha256_t); j++) {
			printf("%02x", key[j]);
		}

		printf("\n");
	}

	printf("\n");

	fsnp_init_ack(&ack);
	w = fsnp_write_msg_tcp(peer_sock, 0, (const struct fsnp_msg *)&ack, &err);
	if (w < 0) {
		fsnp_log_err_msg(err, NULL);
		exit(EXIT_FAILURE);
	}
}

static void update_received(struct fsnp_update *update)
{
	uint32_t i = 0;
	uint32_t j = 0;
	sha256_t key;

	printf("Update message received!\n");
	printf("%u keys received from the peer\n\n", update->num_files);
	for (i = 0; i < update->num_files; i++) {
		printf("%u: ", i);
		memcpy(key, update->files_hash + i * sizeof(sha256_t), sizeof(sha256_t));
		for (j = 0; j < sizeof(sha256_t); j++) {
			printf("%02x", key[j]);
		}

		printf("\n");
	}

	printf("\n");
}

static void read_messages(void)
{
	struct fsnp_msg *msg = NULL;
	ssize_t r = 0;
	fsnp_err_t err;

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-noreturn"
#endif

	while (true) {
		printf("Waiting for a join/update message...\n");
		msg = fsnp_read_msg_tcp(peer_sock, USHRT_MAX, &r, &err);
		if (!msg) {
			fsnp_log_err_msg(err, NULL);
			if (err == E_NOT_FSNP_MSG) {
				exit(EXIT_FAILURE);
			}
			continue;
		}

		if (msg->msg_type == JOIN) {
			join_received((struct fsnp_join *)msg);
		} else if (msg->msg_type == UPDATE) {
			update_received((struct fsnp_update *)msg);
		} else {
			fprintf(stderr, "Unexpected message received\n");
		}

		free(msg);
	}

#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
}

int main(int argc, char **argv)
{
	UNUSED(argc);
	UNUSED(argv);

	connect_to_server();
	wait_for_peer();
	read_messages();
}