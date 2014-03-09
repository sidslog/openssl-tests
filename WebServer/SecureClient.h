//
//  SecureClient.h
//  OpenSSLTests
//
//  Created by sidslog on 09.03.14.
//
//

#ifndef OpenSSLTests_SecureClient_h
#define OpenSSLTests_SecureClient_h

#include <sys/types.h>
#include <pthread.h>
#include "SecurePacket.h"

typedef time_t TIMESTAMP;
typedef char * CLIENT_NAME;



struct session_key_st {
	ssize_t length;
	BYTE_PTR data;
};

typedef struct session_key_st SESSION_KEY;


struct client_context_st {
	SESSION_KEY *public_key;
	SESSION_KEY *private_key;
	SESSION_KEY *session_key;
};

typedef struct client_context_st CLIENT_CONTEXT;

struct secure_client_st {
	char *label;
	in_port_t port;
	pthread_t thread;
	volatile int *stopped;
	CLIENT_CONTEXT *context;
};

typedef struct secure_client_st SECURE_CLIENT;

int client_start(SECURE_CLIENT *client);
void client_stop(SECURE_CLIENT *client);

#pragma mark - helpers

void keypair_gen(SESSION_KEY *public_key, SESSION_KEY *private_key);
SESSION_KEY session_key_create(int length);
void session_key_dump(SESSION_KEY *key);

unsigned char* encode_with_private(BYTE_PTR private_key, int private_key_length);

#pragma mark - Wide-Mouth Frog

void wmf_alice_to_trent(SECURE_CLIENT *alice, SECURE_CLIENT *trent, TIMESTAMP time, CLIENT_NAME bob_name, SESSION_KEY key);

#endif
