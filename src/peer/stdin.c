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
#include "peer/superpeer.h"
#include "peer/peer-server.h"
#include "peer/peer-superpeer.h"
#include "peer/peer-peer.h"
#include "peer/file_manager.h"
#include "peer/superpeer-superpeer.h"

#include "fsnp/fsnp.h"

#include "slog/slog.h"

#define MAX_STDIN_SIZE 32U

static pthread_mutex_t stdin_mtx;

void init_stdin(void)
{
	if (pthread_mutex_init(&stdin_mtx, NULL)) {
		slog_error(FILE_LEVEL, "Unable to initialize the stdin subsystem");
	}
}

void close_stdin(void)
{
	if (pthread_mutex_destroy(&stdin_mtx)) {
		slog_error(FILE_LEVEL, "Unable to close properly the stdin subsystem");
	}
}

void block_stdin(void)
{
	if (pthread_mutex_lock(&stdin_mtx)) {
		slog_error(FILE_LEVEL, "Unable to block the stdin subsystem");
	}
}

void release_stdin(void)
{
	if (pthread_mutex_unlock(&stdin_mtx)) {
		slog_error(FILE_LEVEL, "Unable to release the stdin subsystem");
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
		slog_warn(FILE_LEVEL, "Unable to read stdin. Error returned: %d", errno);
		return 0;
	} else {
		slog_info(FILE_LEVEL, "String read from stdin: %s", msg);
		return strlen(msg);
	}
}

#define IP_STR_SIZE 17
#define PORT_STR_SIZE 7

bool request_user_ip_port(struct sockaddr_in *addr)
{
	char ip[IP_STR_SIZE];
	char port[PORT_STR_SIZE];
	in_port_t p = 0;
	size_t n = 0;

	memset(ip, 0, sizeof(ip));
	memset(port, 0, sizeof(port));

	printf("Insert the IP address: ");
	fflush(stdout);
	slog_debug(FILE_LEVEL, "Reading an IP address");
	n = read_stdin(ip, IP_STR_SIZE);
	if (!n) {
		slog_warn(STDOUT_LEVEL, "An error has occurred while reading the stdin");
		return false;
	}

	if (!inet_aton(ip, &addr->sin_addr)) {
		slog_warn(STDOUT_LEVEL, "The IP address is invalid: %s", ip);
		cleanup_stdin();
		return false;
	}

	// fsnp will take care of the endianness
	addr->sin_addr.s_addr = ntohl(addr->sin_addr.s_addr);
	cleanup_stdin();
	printf("Insert the port: ");
	fflush(stdout);
	slog_debug(FILE_LEVEL, "Reading a port number");
	n = read_stdin(port, PORT_STR_SIZE);
	if (!n) {
		slog_warn(STDOUT_LEVEL, "An error has occurred while reading the stdin");
		return false;
	}

	p = (in_port_t)strtol(port, NULL, 10);
	if (!p) {
		slog_warn(STDOUT_LEVEL, "Invalid port number: %s", port);
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
	query_res = fsnp_create_query_res(0, 1, &peer);
	if (!query_res) {
		slog_warn(STDOUT_LEVEL, "Unable to join");
		slog_error(FILE_LEVEL, "Unable to create query_res: error %d", errno);
		return;
	}

	join_sp(query_res);
	free(query_res);
}

/*
 * Helper function for asking the user a path
 */
static int request_dir(char *path)
{
	size_t l = 0;

	printf("Insert the path: ");
	fflush(stdout);
	slog_debug(FILE_LEVEL, "Reading a path");
	l = read_stdin(path, PATH_MAX - 1);
	if (l == 0) {
		slog_warn(STDOUT_LEVEL, "An error has occurred while reading from the "
						        "stdin");
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
		slog_warn(STDOUT_LEVEL, "An error occurred while parsing the directory");
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
}

#define FILENAME_SIZE 256

/*
 * The user wants to know who has a file in the network
 */

static void who_has_handler(void)
{
	char filename[FILENAME_SIZE];
	size_t s = 0;

	if (get_peer_sock() == 0 && !is_superpeer()) {
		slog_warn(STDOUT_LEVEL, "You have to join a superpeer before searching"
						        " for a file");
		return;
	}

	if (file_already_asked() && !is_superpeer()) {
		slog_info(STDOUT_LEVEL, "You've already asked a file. Wait until a "
						  "response for it arrive before asking for another one");
		return;
	}

	printf("Insert the name of the file (max 255 characters): ");
	fflush(stdout);
	slog_debug(FILE_LEVEL, "Reading file name to search");
	s = read_stdin(filename, FILENAME_SIZE);
	if (s == 0) {
		slog_warn(STDOUT_LEVEL, "An error occurred while reading from the stdin");
		return;
	}

	if (filename[s - 1] == '\n') {
		filename[s - 1] = '\0';
	}

	if (is_superpeer()) {
		sp_ask_file(filename, s);
	} else {
		peer_ask_file(filename, s);
	}
}

/*
 * The user wants to download a file from a peer
 */
static void download_handler(void)
{
	size_t r = 0;
	bool ok = false;
	struct sockaddr_in addr;
	char filename[FSNP_NAME_MAX];
	struct fsnp_peer peer;

	if (get_peer_sock() == 0 && !is_superpeer()) {
		slog_warn(STDOUT_LEVEL, "You have to join a superpeer before downloading"
		                        " a file");
		return;
	}

	ok = request_user_ip_port(&addr);
	if (!ok) {
		slog_warn(FILE_LEVEL, "Unable to read peer's address");
		return;
	}

	cleanup_stdin();
	printf("Insert the name of the file you want to download (max 255 characters): ");
	fflush(stdout);
	slog_debug(FILE_LEVEL, "Reading name of the file to download");
	r = read_stdin(filename, FSNP_NAME_MAX);
	if (r == 0) {
		slog_warn(STDOUT_LEVEL, "An error occurred while reading from the stdin");
		return;
	}

	if (filename[r - 1] == '\n') {
		filename[r - 1] = '\0';
	}

	peer.ip = addr.sin_addr.s_addr;
	peer.port = addr.sin_port;
	dw_from_peer(&peer, filename);
}

/*
 * Print the addresses of the superpeer's neighbors
 */
static void print_known_sp(void)
{
	int ret = 0;
	struct sp_nb_addr sna;

	if (!is_superpeer()) {
		slog_warn(STDOUT_LEVEL, "You're not a superpeer!");
		PRINT_PEER;
		return;
	}

	memset(&sna, 0, sizeof(struct sp_nb_addr));
	ret = get_neighbors_addresses(&sna);
	if (ret < 0) {
		slog_warn(STDOUT_LEVEL, "An error has occurred while getting the"
						  " neighbors' addresses");
		PRINT_PEER;
		return;
	}

	printf("\nself:\t\t%s\nprev:\t\t%s\nnext:\t\t%s\nsnd_next:\t%s\n",
			sna.self, sna.prev, sna.next, sna.snd_next);
}

/*
 * Print the peer's address and all the ports used to listen for connections
 */
static void print_peer_info(void)
{
	struct in_addr ip;
	in_port_t udp_sp_port = 0;
	in_port_t tcp_sp_port = 0;
	in_port_t dw_port = get_dw_port();

	ip.s_addr = htonl(get_peer_ip());
	printf("IP address: %s\nDownload port: %hu\n", inet_ntoa(ip), dw_port);
	if (is_superpeer()) {
		udp_sp_port = get_udp_sp_port();
		tcp_sp_port = get_tcp_sp_port();
		printf("Superpeer UDP port: %hu\nSuperpeer TCP port: %hu\n",
				udp_sp_port, tcp_sp_port);
	}
}

static void show_help(void)
{
	printf("\n"
		   "%-20s %-30s\n\n"
	       "%-20s %-30s\n\n"
	       "%-20s %-30s\n\n"
	       "%-20s %-30s\n\n"
	       "%-20s %-30s\n\n"
	       "%-20s %-30s\n\n"
	       "%-20s %-30s\n\n"
	       "%-20s %-30s\n\n"
	       "%-20s %-30s\n\n"
	       "%-20s %-30s\n",
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
	       "download", "Download a file from a peer",
	       "show_sp", "Show the others superpeers' addresses known by this"
				      " superpeer. This command works only if this executable"
		              " is a superpeer itself",
	       "peer_info", "Show the peer's address and all the ports used to listen"
					 "for connections",
	       "quit", "Close the peer executable");
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
	const char show_sp[] = "show_sp\n";
	const char show_peer_info[] = "peer_info\n";
	const char help[] = "help\n";
	const char quit[] = "quit\n";

	if (!strncmp(msg, query_sp, n)) {
		query_sp_handler();
	} else if (!strncmp(msg, join_sp, n)) {
		join_sp_handler();
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
	} else if (!strncmp(msg, show_sp, n)) {
		print_known_sp();
	} else if (!strncmp(msg, show_peer_info, n)) {
		print_peer_info();
	} else if (!strncmp(msg, help, n)) {
		show_help();
	} else if (!strncmp(msg, quit, n)) {
		quit_peer();
	} else {
		printf("?\n");
		slog_debug(FILE_LEVEL, "Unknown message received");
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
	PRINT_PEER;
}

#undef FILENAME_SIZE
#undef MAX_STDIN_SIZE