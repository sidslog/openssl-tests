//
//  SecurePacket.h
//  OpenSSLTests
//
//  Created by sidslog on 09.03.14.
//
//

#ifndef OpenSSLTests_SecurePacket_h
#define OpenSSLTests_SecurePacket_h

#include <sys/types.h>
#include <stdlib.h>

/* protocol desc
 
 COMMAND IS SENT FROM CLIENT TO CLIENT
 - int32_t command
 - int32_t args count
 - args[] - args
	- int32_t arg length
	- unsigned char *arg
 */

#pragma mark - commands

#define COMMAND_WMF_1 1


#pragma mark - packets

typedef unsigned char * BYTE_PTR;
typedef const unsigned char * CONST_BYTE_PTR;

struct packet_arg_st {
	BYTE_PTR arg;
	int32_t length;
};

typedef struct packet_arg_st PACKET_ARG;

struct packet_st {
	uint32_t command;
	uint32_t args_count;
	PACKET_ARG **args;
};

typedef struct packet_st PACKET;

PACKET* packet_create(uint32_t command);
void packet_free(PACKET *packet);
void packet_add_arg(PACKET *packet, uint32_t arg_length, BYTE_PTR arg_data);

PACKET* packet_read(int socket);
void packet_write(int socket, PACKET *packet);

void bytes_dump(BYTE_PTR data, ssize_t length);
#endif
