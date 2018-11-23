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
 * 1) QUERY: ask to the server to send the superpeers he knows
 *
 * 2) QUERY_RES: server's response to the QUERY message
 *
 * 3) ADD_PEER: tell to the server to add a new superpeer to its list
 *
 * 4) RM_SP: tell the server to remove a superpeer from its list
 *
 * 5) JOIN: a peer asks to a superpeer to join him
 *
 * 6) ACK: an acknowledgment for some protocol's messages
 *
 * 7) LEAVE: tell to the others peers (or superpeers) that the sender is leaving
 *
 * 8) FILE_REQ: ask to a superpeer to search for a file
 *
 * 9) FILE_RES: superpeer's response to FILE_REQ. It contains the list of peers
 *              who are sharing the file requested.
 *
 * 10) UPDATE: communicate to the superpeer that the sender's file list has
 *             changed
 *
 * 11) ALIVE: Check if a peer (or superpeer) is still online
 *
 * 12) GET_FILE: sent to a peer to ask him to initiate a download session for a
 *               given file
 *
 * 13) ERROR: an error messages for some protocol's messages. It's used for
 *            communicating the inability to do an operation
 *
 * 14) DOWNLOAD: sent to a peer who asked a file with GET_FILE. This communicate
 *               to the peer that the download session can be started
 *
 * 15) PROMOTE: promote a peer to be a superpeer
 *
 * 16) PROMOTED: sent by a newly promoted superpeer to its promoter. This
 *               communicate to the promoter that everything went ok while
 *               entering the superpeer_mode
 *
 * 17) NEXT: a superpeer sent this to another to communicate to him that he is
 *           its new next
 *
 * 18) WHOSNEXT: a superpeer is asking to his next who's after him
 *
 * 19) WHOHAS: asks inside the superpeers overlay network who has a file
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
	PROMOTE,
	PROMOTED,
	NEXT,
	WHOSNEXT,
	WHOHAS
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
 * Ask to the server a list of superpeers
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
 * Tell to the server to add a new superpeer to its list.
 */
struct packed fsnp_add_sp {
		struct fsnp_msg header;
		in_port_t p_port; // port for the peers
		in_port_t sp_port; // port for the superpeers
};

/*
 * Tell to the server to remove a superpeer. Based on 'peer_type' the 'port'
 * field inside addr is either the port number used by the peers or the port
 * number used by the superpeers
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
 * Sent by a peer/superpeer when it's leaving the superpeer/network
 */
struct packed fsnp_leave {
		struct fsnp_msg header;
};

/*
 * Ask to the superpeer to find the peers who are sharing the file with the
 * given hash
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
 */
struct packed fsnp_download {
	struct fsnp_msg header;
	uint64_t file_size;
};

/*
 * Sent to a peer by its superpeer to inform him that he is now a superpeer.
 * The promoter, if has a next, will pass it to the promoted so that
 * he can still join the network if something happens to who sent this message
 */
struct packed fsnp_promote {
	struct fsnp_msg header;
	in_port_t sp_port; // the superpeer UDP port of the promoter
	struct fsnp_peer sp;
};

/*
 * This message is sent to the superpeer who has promoted.
 * This is used for letting him know that the procedure for becoming a superpeer
 * has been successful
 */
struct packed fsnp_promoted {
	struct fsnp_msg header;
};

/*
 * This is sent to the superpeer who's going to be the next of the sender.
 * If it contains the address of the previous next, the superpeer who receive
 * this message must contact him for setting old_next as its next.
 * Otherwise, if it's compose by all 0's the receiver will not modify its next
 */
struct packed fsnp_next {
	struct fsnp_msg header;
	struct fsnp_peer old_next;
};

/*
 * A superpeer is asking to his next who's after him.
 * The superpeer who has asked the question fills the 'next' field with all 0's,
 * while the receiver will put the address of its next and will send the message
 * back.
 * This message will be also sent, already filled, to the prev if the next of
 * the next will change.
 */
struct packed fsnp_whosnext {
	struct fsnp_msg header;
	struct fsnp_peer next;
};

/*
 * Sent by a superpeer who's searching a file inside the overlay network.
 * There is a unique ID for the request so that it's impossible to create
 * cycles.
 * The 'sp' field contains the address of the peer who has started the request,
 * so that if num_peers become equals to 10 it can be directly contacted with
 * the data requested.
 */
struct packed fsnp_whohas {
	struct fsnp_msg header;
	struct fsnp_peer sp;
	sha256_t req_id;
	sha256_t file_hash;
	uint8_t num_peers;
	struct fsnp_peer owners[10];
};

FSNP_END_DECL

#endif //FSNP_FSNP_TYPES_H
