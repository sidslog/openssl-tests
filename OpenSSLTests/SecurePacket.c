//
//  SecurePacket.c
//  OpenSSLTests
//
//  Created by sidslog on 09.03.14.
//
//

#include "SecurePacket.h"
#include <stdio.h>

#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

uint32_t read_i(int socket) {
	uint32_t *command = (uint32_t *) malloc(sizeof(uint32_t));
	ssize_t read_count = recv(socket, command, sizeof(uint32_t), 0);
	
	if (read_count != sizeof(uint32_t)) {
		perror("wrong command\n");
		return -1;
	}
	
	int result = *command;
	free(command);
	return result;
}

unsigned char* read_b(int socket, int length) {
	BYTE_PTR buf = malloc(length);
	ssize_t read_count = recv(socket, buf, length, 0);
	if (read_count != length) {
		perror("wrong data\n");
		return NULL;
	}
	return buf;
}

void send_i(int socket, uint32_t data) {
	send(socket, &data, sizeof(uint32_t), 0);
}

void send_d(int socket, uint32_t length, BYTE_PTR  data) {
	send(socket, data, length * sizeof(unsigned char), 0);
}

void arg_dump(PACKET *packet, int i) {
	PACKET_ARG *arg = packet->args[i];
	printf("arg[%i] length = %i\n", i, arg->length);
	printf("arg[%i] data:\n", i);
	bytes_dump(arg->arg, arg->length);
}

void packet_dump(PACKET *packet) {
	printf("packet command: %i\n", packet->command);
	printf("packet args length: %i\n", packet->args_count);
	for (int i = 0; i < packet->args_count; i ++) {
		arg_dump(packet, i);
	}
}

PACKET* packet_read(int socket) {
	PACKET *p = malloc(sizeof(PACKET));
	
	p->command = read_i(socket);
	p->args_count = read_i(socket);
	
	PACKET_ARG **args = malloc(p->args_count * sizeof(PACKET_ARG));
	
	for (uint32_t i = 0; i < p->args_count; i ++) {
		PACKET_ARG *arg = malloc(sizeof(PACKET_ARG));
		arg->length = read_i(socket);
		arg->arg = read_b(socket, arg->length);
		
		args[i] = arg;
	}
	
	p->args = args;
	packet_dump(p);
	return p;
}

void packet_write(int socket, PACKET *packet) {
	send_i(socket, packet->command);
	send_i(socket, packet->args_count);
	
	for (int i = 0; i < packet->args_count; i ++) {
		PACKET_ARG *arg = packet->args[i];
		send_i(socket, arg->length);
		send_d(socket, arg->length, arg->arg);
	}
}


void packet_free(PACKET *packet) {
	for (uint32_t i = 0; i < packet->args_count; i ++) {
		PACKET_ARG *arg = packet->args[i];
		free(arg->arg);
		free(arg);
	}
	free(packet);
}

PACKET* packet_create(uint32_t command) {
	PACKET *packet = malloc(sizeof(PACKET));
	packet->command = command;
	packet->args = NULL;
	packet->args_count = 0;
	return packet;
}

PACKET_ARG* arg_create(int length, BYTE_PTR data) {
	PACKET_ARG *arg = malloc(sizeof(PACKET_ARG));
	arg->length = length;
	arg->arg = malloc(length * sizeof(unsigned char));
	memcpy(arg->arg, data, length);
	return arg;
}

void packet_add_arg(PACKET *packet, uint32_t arg_length, BYTE_PTR arg_data) {
	packet->args_count += 1;
	if (packet -> args) {
		packet->args = realloc(packet->args, packet->args_count * sizeof(PACKET_ARG));
	} else {
		packet->args = malloc(sizeof(PACKET_ARG));
	}
	packet->args[packet->args_count - 1] = arg_create(arg_length, arg_data);
}

void bytes_dump(BYTE_PTR data, ssize_t length) {
	int i;
	printf("bytes dump\n\n");
	
	for (i = 0; i < length; i++)
	{
		printf("%02X", data[i]);
	}
	printf("\n");
	printf("\n");
}

