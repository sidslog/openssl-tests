//
//  SecureClient.c
//  OpenSSLTests
//
//  Created by sidslog on 09.03.14.
//
//

#include "SecureClient.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <netdb.h>
#include <pthread.h>

#include "OpenSSLHelper.h"

void* clientThread(void *arg) {
	SECURE_CLIENT *client = arg;
	
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		perror("couldn't create socket");
		return 0;
	}
		
	struct sockaddr_in address;
	
	/* type of socket created in socket() */
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	
	
	/* port */
	address.sin_port = client->port;
	/* bind the socket to the port specified above */
	bind(sock,(struct sockaddr *)&address,sizeof(address));
	
	printf("bind done\n");
	
	int res = listen(sock, 1000);
	printf("listen done\n");
	if (res == -1) {
		perror("listen");
		return 0;
	}
	
	uint addrlen = sizeof(struct sockaddr_in);
	int new_socket;
	
	*client->stopped = 0;
	
	for (;;) {
		int stopped = *client->stopped;
		if (stopped == 1) {
			break;
		}
		
		printf("pid = %d\n", getpid());
		new_socket = accept(sock, (struct sockaddr *)&address, &addrlen);
		printf("client connected :%d\n", getpid());
		
		if (new_socket<0) {
			perror("Accept connection");
			close(new_socket);
			continue;
		}
		
		PACKET *packet = packet_read(new_socket);
		
		SESSION_KEY *key = client->context->private_key;
		
		BYTE_PTR iv = packet->args[1]->arg;
		uint32_t iv_length = packet->args[1]->length;
		
		BYTE_PTR ek = packet->args[2]->arg;
		uint32_t ek_length = packet->args[2]->length;
		
		BYTE_PTR msg = packet->args[3]->arg;
		uint32_t msg_length = packet->args[3]->length;
		
		
		BYTE_PTR out;
		uint32_t out_length;
		
		data_decode(msg, msg_length, key, iv, iv_length, ek, ek_length, &out, &out_length);
		
		printf("decoded data:\n");
		bytes_dump(out, out_length);
		
		free(out);
		
	}

	close(sock);
	return NULL;
}

int client_start(SECURE_CLIENT *client) {
	int err = pthread_create(&client->thread, NULL, &clientThread, client);
	return err;
}

void client_stop(SECURE_CLIENT *client) {
	*client->stopped = 1;
}

int socket_connect_to_client(SECURE_CLIENT *client) {
	struct hostent     *he;
	struct sockaddr_in  server;

	/* resolve localhost to an IP (should be 127.0.0.1) */
	if ((he = gethostbyname("localhost")) == NULL) {
		puts("error resolving hostname..");
		return 0;;
	}
	
	/*
	 * copy the network address part of the structure to the
	 * sockaddr_in structure which is passed to connect()
	 */
	memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);
	server.sin_family = AF_INET;
	server.sin_port = client->port;

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	int conn = connect(sock, (struct sockaddr *)&server, sizeof(server));
	
	if (conn == -1) {
		perror("connect");
		return 0;
	}

	return sock;
}




void wmf_alice_to_trent(SECURE_CLIENT *alice, SECURE_CLIENT *trent, TIMESTAMP time, CLIENT_NAME bob_name, SESSION_KEY key) {
	PACKET *packet = packet_create(COMMAND_WMF_1);
	
	packet_add_arg(packet, (uint32_t)strlen(alice->label), (BYTE_PTR )alice->label);
	
	int buf_length = (int) (sizeof(time_t) + sizeof(uint32_t) + strlen(bob_name) * sizeof(char) + sizeof(uint32_t) + key.length * sizeof(unsigned char));
	
	BYTE_PTR buf = malloc(buf_length);
	
	uint32_t bob_name_length = (uint32_t) strlen(bob_name);
	
	memcpy(buf, &time, sizeof(time_t));
	memcpy(buf + sizeof(time_t), &bob_name_length, sizeof(uint32_t));
	memcpy(buf + sizeof(time_t) + bob_name_length, (BYTE_PTR )bob_name, strlen(bob_name));
	memcpy(buf + sizeof(time_t) + bob_name_length + strlen(bob_name), &key.length, sizeof(uint32_t));
	memcpy(buf + sizeof(time_t) + bob_name_length + strlen(bob_name) + sizeof(uint32_t), key.data, key.length);
	
	
	BYTE_PTR encrypted;
	BYTE_PTR iv;
	BYTE_PTR ek;
	uint32_t encrypted_length;
	uint32_t iv_length;
	uint32_t ek_length;
	
	data_encode(buf, buf_length, alice->context->public_key, &encrypted, &encrypted_length, &iv, &iv_length, &ek, &ek_length);
	
	bytes_dump(encrypted, encrypted_length);
	
	packet_add_arg(packet, iv_length, iv);
	packet_add_arg(packet, ek_length, ek);
	packet_add_arg(packet, encrypted_length, encrypted);
	
	int sock = socket_connect_to_client(trent);
	
	packet_write(sock, packet);
	
end:
	free(encrypted);
	free(iv);
	free(ek);
	free(buf);
	
	close(sock);
	
}
