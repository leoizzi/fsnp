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

#include "boot_server/server.h"

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

	if (new_port == 0) {
		fprintf(stderr, "Error during the conversion of the string\n");
		exit(EXIT_FAILURE);
	}

	if (new_port < 0 || new_port >= 65535) {
		fprintf(stderr, "The server port range value is 1-65536. You've passed %hu\n", new_port);
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
		fprintf(stderr, "Too many arguments!\n");
		usage();
		exit(EXIT_FAILURE);
	}

	for (i = 1; i < argc; i++) {
		if (!strncmp(argv[i], with_port_opt, sizeof(with_port_opt))) {
			change_default_port(port, argv[i] + sizeof(with_port_opt));
		} else if (!strncmp(argv[i], localhost_opt, sizeof(localhost_opt))) {
			*localhost = true;
		} else if (!strncmp(argv[i], help_opt, sizeof(help_opt))) {
			usage();
			exit(EXIT_SUCCESS);
		} else {
			fprintf(stderr, "Unknown command line argument: %s\n\n", argv[i]);
			usage();
			exit(EXIT_SUCCESS);
		}
	}
}

int main(int argc, char *argv[])
{
	in_port_t port = (in_port_t)SERVER_PORT;
	bool localhost = false;

	server_conf(argc, argv, &port, &localhost);
	return server_main(port, localhost);
}