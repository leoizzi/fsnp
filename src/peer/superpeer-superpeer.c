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

#include "peer/superpeer-superpeer.h"

#include "fsnp/fsnp.h"

int enter_sp_network(int udp, struct fsnp_peer *sps, unsigned n)
{
	if (n == 0) {
		return 0;
	} else {
		return -1;
	}
	// TODO: implement (start another thread here...)
}

/*
 * Exit the superpeer's overlay network. The socket passed when entered will be
 * closed.
 */
void exit_sp_network(void)
{
	// TODO: implement
}