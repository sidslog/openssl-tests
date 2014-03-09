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

#include "openssl/aes.h"

int main(int argc, const char * argv[])
{

	
	unsigned char *in = (unsigned char *)"12312312312321";
    
	unsigned char * enc_out = malloc(80*sizeof(char));
    unsigned char * dec_out = malloc(80*sizeof(char));
	
	
	AES_KEY key;
	unsigned char *userkey = (unsigned char *)"123";
	AES_set_encrypt_key(userkey, 256, &key);
	
	AES_encrypt(in, enc_out, &key);
	
	printf("out: %s", enc_out);
	
	AES_set_decrypt_key(userkey, 256, &key);
	AES_decrypt(enc_out, dec_out, &key);
	printf("in: %s", dec_out);
	
	// insert code here...
	printf("Hello, World!\n");
	
	signal(SIGCHLD,SIG_IGN);	/* to avoid zombies */
	
	startServer(htons(7005));
	
    return 0;
}

