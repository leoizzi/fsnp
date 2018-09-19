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
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "peer/peer.h"

static void usage(void)
{
	printf("Usage: peer [--localhost] [--help]\n\n"
	       "localhost\t\tIf enabled the peer will be listening for messages only on the loopback interface\n"
	       "help     \t\tShow this message\n\n");
}

static void peer_conf(int argc, char *argv[], bool *localhost)
{
	const char localhost_opt[] = "--localhost";
	const char help_opt[] = "--help";
	int i;

	for (i = 1; i < argc; i++) {
		if (!strncmp(argv[i], help_opt, sizeof(help_opt))) {
			usage();
			exit(EXIT_SUCCESS);
		} else if (!strncmp(argv[i], localhost_opt, sizeof(localhost_opt))) {
			*localhost = true;
		} else {
			fprintf(stderr, "Unknown command line argument: %s\n\n", argv[i]);
			usage();
			exit(EXIT_SUCCESS);
		}
	}
}

int main(int argc, char *argv[])
{
	bool localhost = false;

	peer_conf(argc, argv, &localhost);
	return peer_main(localhost);
}