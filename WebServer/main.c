//
//  main.c
//  WebServer
//
//  Created by sidslog on 02.03.14.
//
//

#include "Server.h"
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "SecureClient.h"

int main(int argc, const char * argv[])
{

	// insert code here...
	printf("Hello, World!\n");
	
	SESSION_KEY public_key;
	SESSION_KEY private_key;
	
	keypair_gen(&public_key, &private_key);

	session_key_dump(&public_key);
	session_key_dump(&private_key);
	
	SECURE_CLIENT *alice = malloc(sizeof(SECURE_CLIENT));
	alice->label = "Alice";
	alice->port = htons(7007);
	alice->stopped = malloc(sizeof(int));
	
	alice->context = malloc(sizeof(CLIENT_CONTEXT));
	alice->context->public_key = &public_key;
	
	SECURE_CLIENT *trent = malloc(sizeof(SECURE_CLIENT));
	trent->label = "Trent";
	trent->port = htons(7008);
	trent->stopped = malloc(sizeof(int));

	trent->context = malloc(sizeof(CLIENT_CONTEXT));
	trent->context->private_key = &private_key;
	
	client_start(alice);
	client_start(trent);
	
	SESSION_KEY alicesSessionKey = session_key_create(128);
	
	wmf_alice_to_trent(alice, trent, time(NULL), "Bob", alicesSessionKey);
	
	sleep(100);
	
    return 0;
}

