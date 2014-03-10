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
#include <time.h>

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
	client->socket = sock;
	
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
		client->func(packet, client);
		
		packet_free(packet);
		close(new_socket);
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
	close(client->socket);
}

SECURE_CLIENT *client_by_label(char *label) {
	for (int i = 0; i < clients_count; i ++) {
		SECURE_CLIENT *client = clients[i];
		if (strcmp(client->label, label) == 0) {
			return client;
		}
	}
	perror("client not found");
	return NULL;
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



