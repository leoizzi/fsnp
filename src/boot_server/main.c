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
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <time.h>

#include "boot_server/server.h"

#include "slog/slog.h"

static void usage()
{
	printf("Usage: boot_server [--with_port=<value>] [--localhost] [--help]\n\n"
		   "with_port\t\tOverride the default listening port of the server (%hu)\n"
	       "localhost\t\tIf enabled the server will be listening for messages only on the loopback interface\n"
		   "help     \t\tShow this message\n\n"
		   , (uint16_t)SERVER_PORT);
}

static void change_default_port(in_port_t *port, char *arg)
{
	in_port_t new_port = 0;

	new_port = (in_port_t)strtol(arg, NULL, 10);

	slog_info(FILE_LEVEL, "Change of default port requested: %s", arg);
	if (new_port == 0) {
		slog_warn(STDOUT_LEVEL, "Error during the conversion of the string");
		slog_close();
		exit(EXIT_FAILURE);
	}

	if (new_port < 1024 || new_port >= 65535) {
		slog_warn(STDOUT_LEVEL, "The server port range value is 1024-65535."
						   " You've passed %hu", new_port);
		slog_close();
		exit(EXIT_FAILURE);
	}

	*port = new_port;
}

/*
 * Read the arguments from the command line and set up the server basic
 * configuration
 */
static void server_conf(int argc, char **argv, in_port_t *port, bool *localhost)
{
	int i = 0;
	const char with_port_opt[] = "--with_port=";
	const char localhost_opt[] = "--localhost";
	const char help_opt[] = "--help";

	if (argc > 4) {
		slog_warn(STDOUT_LEVEL, "Too many arguments!");
		usage();
		slog_close();
		exit(EXIT_FAILURE);
	}

	for (i = 1; i < argc; i++) {
		if (!strncmp(argv[i], with_port_opt, sizeof(with_port_opt))) {
			change_default_port(port, argv[i] + sizeof(with_port_opt));
		} else if (!strncmp(argv[i], localhost_opt, sizeof(localhost_opt))) {
			slog_info(FILE_LEVEL, "localhost option enabled");
			*localhost = true;
		} else if (!strncmp(argv[i], help_opt, sizeof(help_opt))) {
			usage();
			slog_info(FILE_LEVEL, "Print usage");
			slog_close();
			exit(EXIT_SUCCESS);
		} else {
			slog_warn(STDOUT_LEVEL, "Unknown command line argument: %s\n\n", argv[i]);
			slog_close();
			usage();
			exit(EXIT_SUCCESS);
		}
	}
}

/*
 * Initialize the slog library
 */
static void start_log(void)
{
	slog_init("server_log", NULL, MAX_LOG_STDOUT_LEVEL, 1);
}

int main(int argc, char *argv[])
{
	in_port_t port = (in_port_t)SERVER_PORT;
	bool localhost = false;

	start_log();
	server_conf(argc, argv, &port, &localhost);
	return server_main(port, localhost);
}