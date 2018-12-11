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

#include "fsnp/fsnp_types.h"

int main (int argc, char *argv[])
{
	unsigned i = 0;
	const char *names[] = {
			"QUERY",
			"QUERY_RES",
			"ADD_SP",
			"RM_SP",
			"JOIN",
			"ACK",
			"LEAVE",
			"FILE_REQ",
			"FILE_RES",
			"UPDATE",
			"ALIVE",
			"GET_FILE",
			"ERROR",
			"DOWNLOAD",
			"PROMOTE",
			"PROMOTED",
			"NEXT",
			"WHOSNEXT",
			"WHOHAS"
	};

	const fsnp_type_t values[] = {
			QUERY,
			QUERY_RES,
			ADD_SP,
			RM_SP,
			JOIN,
			ACK,
			LEAVE,
			FILE_REQ,
			FILE_RES,
			UPDATE,
			ALIVE,
			GET_FILE,
			ERROR,
			DOWNLOAD,
			PROMOTE,
			PROMOTED,
			NEXT,
			WHOSNEXT,
			WHOHAS
	};

	UNUSED(argc);
	UNUSED(argv);

	for (i = 0; i < sizeof(values) / sizeof(fsnp_type_t); i++) {
		printf("%s -> %u\n", names[i], values[i]);
	}
}

