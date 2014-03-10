//
//  SecureClient.h
//  OpenSSLTests
//
//  Created by sidslog on 09.03.14.
//
//

#ifndef OpenSSLTests_SecureClient_h
#define OpenSSLTests_SecureClient_h

#include "SecurePacket.h"


struct client_context_st {
	SESSION_KEY *public_key;
	SESSION_KEY *private_key;
	SESSION_KEY *session_key;
};

typedef struct client_context_st CLIENT_CONTEXT;

typedef void (*rcv_func)(PACKET *, void *);

struct secure_client_st {
	char *label;
	in_port_t port;
	pthread_t thread;
	volatile int *stopped;
	CLIENT_CONTEXT *context;
	rcv_func func;
	int socket;
};

typedef struct secure_client_st SECURE_CLIENT;

// clients storage
SECURE_CLIENT **clients;
int clients_count;

// clients actions
int client_start(SECURE_CLIENT *client);
void client_stop(SECURE_CLIENT *client);

// helpers
SECURE_CLIENT *client_by_label(char *label);
int socket_connect_to_client(SECURE_CLIENT *client);

#endif
