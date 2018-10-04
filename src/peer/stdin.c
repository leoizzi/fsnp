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
#include <string.h>
#include <stdbool.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <limits.h>

#include "peer/stdin.h"
#include "peer/peer.h"
#include "peer/peer-server.h"
#include "peer/peer-superpeer.h"
#include "peer/file_manager.h"

#include "fsnp/fsnp.h"

#define MAX_STDIN_SIZE 32U

static pthread_mutex_t stdin_mtx;

void init_stdin(void)
{
	if (pthread_mutex_init(&stdin_mtx, NULL)) {
		fprintf(stderr, "Unable to initialize the stdin subsystem\n");
	}
}

void close_stdin(void)
{
	if (pthread_mutex_destroy(&stdin_mtx)) {
		fprintf(stderr, "Unable to close properly the stdin subsystem");
	}
}

void block_stdin(void)
{
	if (pthread_mutex_lock(&stdin_mtx)) {
		fprintf(stderr, "Unable to block the stdin subsystem\n");
	}
}

void release_stdin(void)
{
	if (pthread_mutex_unlock(&stdin_mtx)) {
		fprintf(stderr, "Unable to release the stdin subsystem\n");
	}
}

/*
 * Used only by the main thread. If the mutex is locked skip the read
 */
static bool tryblock_stdin(void)
{
	if(!pthread_mutex_trylock(&stdin_mtx)) {
		return true;
	} else {
		return false;
	}
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
 * Read at maximum size bytes from the stdin and put them inside msg.
 * Returns 0 on error, the length of the string otherwise
 */
static size_t read_stdin(char *msg, int size)
{
	if (!fgets(msg, size, stdin)) {
		return 0;
	} else {
		return strlen(msg);
	}
}

#define IP_STR_SIZE 16
#define PORT_STR_SIZE 6

/*
 * Ask the user to give us an IP address and a port
 */
static bool request_user_ip_port(struct sockaddr_in *addr)
{
	char ip[IP_STR_SIZE];
	char port[PORT_STR_SIZE];
	in_port_t p = 0;
	size_t n = 0;

	memset(ip, 0, sizeof(ip));
	memset(port, 0, sizeof(port));

	printf("Insert the IP address: ");
	fflush(stdout);
	n = read_stdin(ip, IP_STR_SIZE);
	if (!n) {
		fprintf(stderr, "An error has occurred while reading the stdin\n");
		return false;
	}

	if (!inet_aton(ip, &addr->sin_addr)) {
		fprintf(stderr, "Invalid IP address: %s\n", ip);
		cleanup_stdin();
		return false;
	}

	// fsnp will take care of the endianness
	addr->sin_addr.s_addr = ntohl(addr->sin_addr.s_addr);
	cleanup_stdin();
	printf("Insert the port: ");
	fflush(stdout);
	n = read_stdin(port, PORT_STR_SIZE);
	if (!n) {
		fprintf(stderr, "An error has occurred while reading the stdin\n");
		return false;
	}

	p = (in_port_t)strtol(port, NULL, 10);
	if (!p) {
		fprintf(stderr, "Invalid port number: %s\n", port);
		cleanup_stdin();
		return false;
	}

	cleanup_stdin();
	addr->sin_port = p; // fsnp will take care of the endianness
	return true;
}

/*
 * The user asked to query the sp from the boot server
 */
static void query_sp_handler(void)
{
	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(addr));
	if (!request_user_ip_port(&addr)) {
		return;
	}

	launch_query_server_sp(&addr);
}

/*
 * The user asked to join a superpeer
 */
static void join_sp_handler(void)
{
	struct sockaddr_in addr;
	struct fsnp_peer peer;
	struct fsnp_query_res *query_res;

	if (!request_user_ip_port(&addr)) {
		return;
	}

	peer.ip = addr.sin_addr.s_addr;
	peer.port = addr.sin_port;
	query_res = fsnp_create_query_res(1, &peer);
	if (!query_res) {
		fprintf(stderr, "Unable to join\n");
		return;
	}

	join_sp(query_res);
	free(query_res);
}

/*
 * Only if superpeer: print on the stdout the list of known superpeer
 */
static void show_sp_list(void)
{
	if (!is_superpeer()) {
		return;
	}

	// TODO: implement
}

/*
 * Helper function for asking the user a path
 */
static int request_dir(char *path)
{
	size_t l = 0;

	printf("Insert the path: ");
	fflush(stdout);
	l = read_stdin(path, PATH_MAX - 1);
	if (l == 0) {
		fprintf(stderr, "An error has occurred while reading from the stdin\n");
		return -1;
	}

	l = strnlen(path, PATH_MAX - 1) - 1;
	if (path[l] == '\n') {
		path[l] = '\0';
	}

	if (path[l - 1] != '/') {
		path[l] = '/';
		// safe to do since read_stdin has read at max PATH-1 bytes
		path[l + 1] = '\0';
	}

	return 0;
}

/*
 * The user wants to update the directory of shared files
 */
static void update_shared_dir(void)
{
	char path[PATH_MAX];
	int ret = 0;

	if (request_dir(path) < 0) {
		return;
	}

	ret = set_shared_dir(path);
	if (ret < 0) {
		perror("An error occurred while parsing the directory");
	}
}

/*
 * The user wants to update the directory where to download files
 */
static void update_download_dir(void)
{
	char path[PATH_MAX];
	int ret = 0;

	ret = request_dir(path);
	if (ret < 0) {
		return;
	} else if (ret == 1) {
		set_download_dir(NULL);
	} else {
		set_download_dir(path);
	}
}

/*
 * The user wants to know the directory where the files are downloaded
 */
static void print_download_path(void)
{
	show_download_path();
	printf("\nPeer: ");
	fflush(stdout);
}

/*
 * The user wants to know who has a file in the network
 */
static void who_has_handler(void)
{
	// TODO: implement
}

/*
 * The user wants to download a file from a peer
 */
static void download_handler(void)
{
	// TODO: implement
}


static void show_help(void)
{
	printf("\n"
		   "%-10s %-30s\n\n"
	       "%-10s %-30s\n\n"
	       "%-10s %-30s\n\n"
	       "%-10s %-30s\n\n"
	       "%-10s %-30s\n\n"
	       "%-10s %-30s\n\n"
	       "%-10s %-30s\n\n"
	       "%-10s %-30s\n\n"
	       "%-10s %-30s\n",
	       "query_sp", "Contact the bootstrap server to get a list of superpeer",
	       "join_sp", "Join a superpeer",
	       "shared_dir", "Set the directory where are located the file to share."
					     " This directory can be left unset (although this is a "
		                 "selfish decision)",
	       "download_dir", "Set the directory where to save the files. By "
						   "default is set to be the directory where this"
		                   " executable is located",
	       "show_download_path", "Show the path of the download directory",
	       "who_has", "Search inside the network who has a file",
	       "download", "download a file from a peer",
	       "list_sp", "Show the list of superpeers known by this superpeer",
	       "quit", "Exit the peer executable");
}

/*
 * Parse the message from the user and call the right handler
 */
static void parse_msg(const char *msg, size_t n)
{
	const char query_sp[] = "query_sp\n";
	const char join_sp[] = "join_sp\n";
	const char shared_dir[] = "shared_dir\n";
	const char download_dir[] = "download_dir\n";
	const char show_download_path[] = "show_download_path\n";
	const char who_has[] = "who_has\n";
	const char download[] = "download\n";
	const char list_sp[] = "list_sp\n";
	const char help[] = "help\n";
	const char quit[] = "quit\n";

	if (!strncmp(msg, query_sp, n)) {
		query_sp_handler();
	} else if (!strncmp(msg, join_sp, n)) {
		join_sp_handler();
	} else if (!strncmp(msg, list_sp, n)) {
		show_sp_list();
	} else if (!strncmp(msg, shared_dir, n)) {
		update_shared_dir();
	} else if (!strncmp(msg, download_dir, n)) {
		update_download_dir();
	} else if (!strncmp(msg, show_download_path, n)) {
		print_download_path();
	} else if (!strncmp(msg, who_has, n)) {
		who_has_handler();
	} else if (!strncmp(msg, download, n)) {
		download_handler();
	} else if (!strncmp(msg, help, n)) {
		show_help();
	} else if (!strncmp(msg, quit, n)) {
		quit_peer();
	} else {
		printf("?\n");
	}
}

void stdin_event(void)
{
	char msg[MAX_STDIN_SIZE];
	size_t n = 0;

	memset(msg, 0, sizeof(msg));
	if (!tryblock_stdin()) {
		return;
	}

	n = read_stdin(msg, MAX_STDIN_SIZE);
	release_stdin();
	if (n == 0) {
		fprintf(stderr, "Unable to read data from the stdin\n");
		return;
	}

	parse_msg(msg, n);

	cleanup_stdin();

	printf("\nPeer: ");
	fflush(stdout);
}