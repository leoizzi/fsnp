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
#include <errno.h>

#include "fsnp/fsnp_err.h"

static void print_e_errno_err(void)
{
	fprintf(stderr, "fsnp error type: E_ERRNO. errno value: %d.\n", errno);
	perror("Explanation");
}

static void print_e_timeout_err(void)
{
	fprintf(stderr, "fsnp error type: E_TIMEOUT.\nExplanation: A connection's"
				 " timer has fired. That could happens because the network have"
	             " lost the packet, or because the other host had some kind of"
			     " trouble.\n");
}

static void print_e_not_fsnp_msg_err(void)
{
	fprintf(stderr, "fsnp error type: E_NOT_FSNP_MSG.\nExplanation: The message"
				    " received is not part of the fsnp protocol\n");
}

static void print_e_out_of_mem_err(void)
{
	fprintf(stderr, "fsnp error type: E_OUT_OF_MEM.\nExplanation: The system is"
				    " out of memory. Try to kill some executables, or to reset"
		            " the system\n");
}

static void print_e_peer_disconnected(void)
{
	fprintf(stderr, "fsnp error type: E_PEER_DISCONNECTED.\nExplanation: The "
				    "peer connected has closed its socket.\n");
}

static void print_e_unknown(void)
{
	fprintf(stderr, "fsnp error type: E_UNKNOWN.\nExplanation: An unknown error"
				    " to the protocol has happened.\n");
}

static void print_e_invalid_param(void)
{
	fprintf(stderr, "fsnp error type: E_INVALID_PARAM.\nExplanation: An invalid"
				 " parameter was passed to a function.\n");
}

static void print_default(void) {
	fprintf(stderr, "fsnp error type: unknown fsnp_err_t passed!\n");
}

void fsnp_print_err_msg(fsnp_err_t err)
{
	switch (err) {
		case E_NOERR:
			return;

		case E_ERRNO:
			print_e_errno_err();
			break;

		case E_TIMEOUT:
			print_e_timeout_err();
			break;

		case E_NOT_FSNP_MSG:
			print_e_not_fsnp_msg_err();
			break;

		case E_OUT_OF_MEM:
			print_e_out_of_mem_err();
			break;

		case E_PEER_DISCONNECTED:
			print_e_peer_disconnected();
			break;

		case E_UNKNOWN:
			print_e_unknown();
			break;

		case E_INVALID_PARAM:
			print_e_invalid_param();

		default:
			print_default();
			break;
	}
}