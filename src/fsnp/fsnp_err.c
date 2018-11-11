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
#include <stdbool.h>

#include "fsnp/fsnp_err.h"

#include "slog/slog.h"

static void log_e_errno_err(int level)
{
	slog_warn(level, "fsnp error type: E_ERRNO. errno value: %d.", errno);
}

static void log_e_timeout_err(int level)
{
	slog_warn(level, "fsnp error type: E_TIMEOUT.\nExplanation: A connection's"
				 " timer has fired. That could happens because the network have"
	             " lost the packet, or because the other host had some kind of"
			     " trouble.");
}

static void log_e_not_fsnp_msg_err(int level)
{
	slog_warn(level, "fsnp error type: E_NOT_FSNP_MSG.\nExplanation: The message"
				    " received is not part of the fsnp protocol");
}

static void log_e_out_of_mem_err(int level)
{
	slog_warn(level, "fsnp error type: E_OUT_OF_MEM.\nExplanation: The system is"
				    " out of memory. Try to kill some executables, or to reset"
		            " the system");
}

static void log_e_peer_disconnected(int level)
{
	slog_warn(level, "fsnp error type: E_PEER_DISCONNECTED.\nExplanation: The "
				    "peer connected has closed its socket.");
}

static void log_e_unknown(int level)
{
	slog_warn(level, "fsnp error type: E_UNKNOWN.\nExplanation: An unknown error"
				    " to the protocol has happened.\n");
}

static void log_e_invalid_param(int level)
{
	slog_warn(level, "fsnp error type: E_INVALID_PARAM.\nExplanation: An invalid"
				 " parameter was passed to a function.\n");
}

static void log_e_msg_too_big(int level)
{
	slog_warn(level, "fsnp error type: E_MSG_TOO_BIG.\nExplanation: The message"
				  "was too big to be sent by UDP.");
}

static void log_default(int level) {
	slog_warn(level, "fsnp error type: unknown fsnp_err_t passed!\n");
}

void fsnp_log_err_msg(fsnp_err_t err, bool to_print)
{
	int level = to_print ? STDOUT_LEVEL : FILE_LEVEL;

	switch (err) {
		case E_NOERR:
			return;

		case E_ERRNO:
			log_e_errno_err(level);
			break;

		case E_TIMEOUT:
			log_e_timeout_err(level);
			break;

		case E_NOT_FSNP_MSG:
			log_e_not_fsnp_msg_err(level);
			break;

		case E_OUT_OF_MEM:
			log_e_out_of_mem_err(level);
			break;

		case E_PEER_DISCONNECTED:
			log_e_peer_disconnected(level);
			break;

		case E_UNKNOWN:
			log_e_unknown(level);
			break;

		case E_INVALID_PARAM:
			log_e_invalid_param(level);
			break;

		case E_MSG_TOO_BIG:
			log_e_msg_too_big(level);
			break;

		default:
			log_default(level);
			break;
	}
}