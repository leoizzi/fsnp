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

#ifndef FSNP_FSNP_TYPES_H
#define FSNP_FSNP_TYPES_H

#include <stdint.h>
#include <arpa/inet.h>

#include "compiler.h"
#include "sha-256.h"

FSNP_BEGIN_DECL

/*
 * fsnp messages type.
 *
 * 1) QUERY: ask the server to send the superpeers he knows
 *
 * 2) QUERY_RES: server's response to the QUERY message
 *
 * 3) ADD_PEER: tell the server to add a new superpeer to its list
 *
 * 4) RM_SP: tell the server to remove a superpeer from its list
 *
 * 5) JOIN: a peer asks a superpeer to join him
 *
 * 6) ACK: an acknowledgment for some protocol's messages
 *
 * 7) LEAVE: tell to others peers (or superpeers) that the message sender is
 *           leaving the network
 *
 * 8) FILE_REQ: ask a superpeer to find a file
 *
 * 9) FILE_RES: tell the peer the lists of peers who own the file he requested
 *
 * 10) UPDATE: communicate to the superpeer that the sender's file list is changed
 *
 * 11) ALIVE: Check if a peer is still online
 *
 * 12) GET_FILE: ask a peer to create a download session for a file he owns
 *
 * 13) ERROR: the file requested with GET_FILE isn't available
 *
 * 14) DOWNLOAD: tell the peer that he can start the download
 *
 * 15) WHOHAS: asks inside the superpeers overlay network who has a file
 *
 * 16) PROMOTE: promote a peer to be a superpeer
 */
enum fsnp_type {
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
	WHOHAS,
	PROMOTE
};
typedef enum fsnp_type fsnp_type_t;

#define FSNP_MAGIC "FSNP"
#define FSNP_MAGIC_SIZE 4

/*
 * The base message.
 * It contains an header for identifying it as a valid fsnp message,
 * the type of the message (fsnp_type) and the message size (size of fsnp_msg
 * excluded).
 */
struct packed fsnp_msg {
		uint8_t magic[FSNP_MAGIC_SIZE]; // "FSNP"
		uint32_t msg_type;
		uint64_t msg_size;
};

/*
 * Keep the info of a peer
 */
struct packed fsnp_peer {
		in_addr_t ip;
		in_port_t port;
};

/*
 * Specifies the type of a peer
 */
enum fsnp_peer_type {
	PEER,
	SUPERPEER
};
typedef enum fsnp_peer_type fsnp_peer_type_t;

/*
 * Asks to the server a list of superpeers
 */
struct packed fsnp_query {
		struct fsnp_msg header;
		uint8_t peer_type;
};

/*
 * Sent as response to fsnp_query
 * It contains a variable length array of superpeers and the address of the peer
 * used for contacting the server (in little endian format).
 *
 * The value of the port field inside fsnp_peer depends on peer_type requested:
 * - if the type is peer it will contains the port used by the superpeer for
 *   talking with the peers
 *
 * - if the type is superpeer it will contains the port used by the superpeer
 *   for communicating with others superpeer
 */
struct packed fsnp_query_res {
		struct fsnp_msg header;
		in_addr_t peer_addr;
		uint8_t num_sp;
		struct fsnp_peer sp_list[1];
};

/*
 * Tell the server to add a new superpeer to its list.
 */
struct packed fsnp_add_sp {
		struct fsnp_msg header;
		in_port_t p_port; // port for the peers
		in_port_t sp_port; // port for the superpeers
};

/*
 * Tell the server to remove a superpeer. Based on 'peer_type' the 'port' field
 * inside addr is either the port number used by the peers or the port number
 * used by the superpeers
 */
struct packed fsnp_rm_sp {
		struct fsnp_msg header;
		struct fsnp_peer addr;
		uint8_t peer_type;
};

/*
 * Send to the superpeer the files' hashes which is sharing
 */
struct packed fsnp_join {
		struct fsnp_msg header;
		uint32_t num_files;
		uint8_t files_hash[1];
};

/*
 * Acknowledgment message
 */
struct packed fsnp_ack {
		struct fsnp_msg header;
};

/*
 * Sent by a peer/superpeer when it's leaving the network
 */
struct packed fsnp_leave {
		struct fsnp_msg header;
};

/*
 * Ask the superpeer to find the peers who are sharing the file with the given
 * hash
 */
struct packed fsnp_file_req {
		struct fsnp_msg header;
		sha256_t hash;
};

/*
 * Tell to the peer who made a file request the list of peers who are sharing
 * the file
 */
struct packed fsnp_file_res {
		struct fsnp_msg header;
		uint8_t num_peers;
		struct fsnp_peer peers[1];
};

/*
 * Tell the superpeer to update the file list of the peer who sent the message.
 */
struct packed fsnp_update {
		struct fsnp_msg header;
		uint32_t num_files;
		uint8_t files_hash[1];
};

/*
 * Ask to another peer/superpeer if he's still on
 */
struct packed fsnp_alive {
		struct fsnp_msg header;
};

/*
 * Sent to a peer for asking to start a download session for a given file
 */
struct packed fsnp_get_file {
	struct fsnp_msg header;
	sha256_t hash;
};

/*
 * Sent as response to fsnp_get_file in case the file is not available
 */
struct packed fsnp_error {
	struct fsnp_msg header;
};

/*
 * Sent as response to fsnp_get_file in case the file is available.
 * In dw_port is indicated the port where to contact the peer for downloading
 * the file requested.
 */
struct packed fsnp_download {
	struct fsnp_msg header;
	uint64_t file_size;
	uint16_t dw_port;
};

/*
 * Sent by a superpeer searching a given file inside the overlay network.
 * There is a unique ID for the request so that it's impossible to create cycles
 * and a missing peers field, in order to propagate uselessly the message if
 * enough peers were collected before.
 */
struct packed fsnp_whohas {
	struct fsnp_msg header;
	sha256_t req_id;
	sha256_t file_hash;
	uint8_t missing_peers;

};

/*
 * Sent to a peer by a superpeer to inform him that he is now a superpeer.
 * The promoter, if know another superpeer, will pass it to the promoted so that
 * he can still communicate with the network if the promoter will leave.
 */
struct packed fsnp_promote {
	struct fsnp_msg header;
	in_port_t sp_port; // the superpeer UDP port of the promoter
	struct fsnp_peer sp;
};

FSNP_END_DECL

#endif //FSNP_FSNP_TYPES_H
