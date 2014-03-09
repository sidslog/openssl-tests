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

#include "../Lib/openssl-xcode/openssl/include/openssl/rsa.h"
#include "../Lib/openssl-xcode/openssl/include/openssl/pem.h"
#include "../Lib/openssl-xcode/openssl/include/openssl/rand.h"
#include "../Lib/openssl-xcode/openssl/include/openssl/bn.h"
#include "../Lib/openssl-xcode/openssl/include/openssl/evp.h"

#include "SecurePacket.h"

void data_decode(BYTE_PTR encMsg, uint32_t encMsgLen, SESSION_KEY *key, BYTE_PTR iv, size_t ivl, BYTE_PTR ek, uint32_t ekl, unsigned char **decMsg, uint32_t *dec_msg_length);

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

void session_key_dump(SESSION_KEY *key) {
	bytes_dump(key->data, key->length);
}

void keypair_gen(SESSION_KEY *public_key, SESSION_KEY *private_key) {
	RSA *rsa = RSA_new();
	
	BIGNUM *e = NULL;
	
	e = BN_new();
	BN_set_word(e, RSA_F4);

	if (!RSA_generate_key_ex(rsa, 1024, e, NULL)) {
		perror("error in RSA_generate_key_ex");
	}
	
	
	BYTE_PTR pData = NULL;
	int length = i2d_RSAPublicKey(rsa, NULL);
	
	BYTE_PTR p = pData = malloc(length * sizeof(unsigned char));
	
	public_key->length = i2d_RSAPublicKey(rsa, &pData);
	public_key->data = p;
	
	pData = NULL;
	length = i2d_RSAPrivateKey(rsa, NULL);
	p = pData = malloc(length * sizeof(unsigned char));
	
	private_key->length = i2d_RSAPrivateKey(rsa, &pData);
	private_key->data = p;

}

SESSION_KEY session_key_create(int length) {
	BYTE_PTR key = malloc(length * sizeof(unsigned char));
	RAND_bytes(key, length);
	
	SESSION_KEY sKey;
	sKey.length = length;
	sKey.data = key;
	
	return sKey;
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


void data_decode(BYTE_PTR encMsg, uint32_t encMsgLen, SESSION_KEY *key, BYTE_PTR iv, size_t ivl, BYTE_PTR ek, uint32_t ekl, BYTE_PTR *decMsg, uint32_t *dec_msg_length) {
	
    size_t decLen   = 0;
    size_t blockLen = 0;
    EVP_PKEY *pkey;
	
	EVP_CIPHER_CTX *rsaDecryptCtx;
	rsaDecryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(rsaDecryptCtx);

	
  	RSA *rsa = NULL;
	BYTE_PTR p = key->data;
	rsa = d2i_RSAPrivateKey(NULL, (const unsigned char **) &p, key->length);

	pkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(pkey, rsa))
    {
        perror("EVP_PKEY_assign_RSA");
		return;
    }

	*decMsg = (unsigned char*)malloc(encMsgLen + ivl);
	
    if(!EVP_OpenInit(rsaDecryptCtx, EVP_aes_256_cbc(), ek, (int)ekl, iv, pkey)) {
		perror("EVP_OpenInit");
		return;
    }
	
    if(!EVP_OpenUpdate(rsaDecryptCtx, (unsigned char*)*decMsg + decLen, (int*)&blockLen, encMsg, (int)encMsgLen)) {
		perror("EVP_OpenUpdate");
		return;
    }
    decLen += blockLen;
	
    if(!EVP_OpenFinal(rsaDecryptCtx, (unsigned char*)*decMsg + decLen, (int*)&blockLen)) {
		perror("EVP_OpenFinal");
		return;
    }
    decLen += blockLen;
	
    EVP_CIPHER_CTX_cleanup(rsaDecryptCtx);
	*dec_msg_length	= decLen;
}

void data_encode(BYTE_PTR data, ssize_t data_length, SESSION_KEY *public_key, BYTE_PTR *enc_msg, uint32_t *enc_msg_length, BYTE_PTR *iv, uint32_t *ivl, BYTE_PTR *ek, uint32_t *ekl) {
	
	session_key_dump(public_key);
	
	printf("will encode data:\n");
	bytes_dump(data, data_length);

	printf("with key:\n");
	bytes_dump(public_key->data, public_key->length);

	RSA *rsa = NULL;
	BYTE_PTR p = public_key->data;
	rsa = d2i_RSAPublicKey(NULL, (const unsigned char **) &p, public_key->length);
	
	*ivl = EVP_MAX_IV_LENGTH;
	
	EVP_PKEY *pkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(pkey, rsa))
    {
        perror("EVP_PKEY_assign_RSA");
		return;
    }
	
	EVP_CIPHER_CTX *rsaEncryptCtx;
	rsaEncryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(rsaEncryptCtx);
	
    uint32_t encMsgLen = 0;
    size_t blockLen  = 0;
	
	*ekl = EVP_PKEY_size(pkey);
	
    *ek = (unsigned char*)malloc(*ekl);
    BYTE_PTR iv_data = (unsigned char*)malloc(EVP_MAX_IV_LENGTH);
    if(ek == NULL || iv == NULL) {
		perror("malloc error");
		return	;
	};
		
    BYTE_PTR encMsg = malloc(data_length + EVP_MAX_IV_LENGTH);
    if(encMsg == NULL) {
		perror("malloc2 error");
		return	;
	}
	
    if(!EVP_SealInit(rsaEncryptCtx, EVP_aes_256_cbc(), ek, (int*) ekl, iv_data, &pkey, 1)) {
		perror("EVP_SealInit");
        return;
    }
	
    if(!EVP_SealUpdate(rsaEncryptCtx, encMsg + encMsgLen, (int*)&blockLen, (const unsigned char*)data, data_length)) {
		perror("EVP_SealUpdate");
        return;
    }
    encMsgLen += blockLen;
	
    if(!EVP_SealFinal(rsaEncryptCtx, encMsg + encMsgLen, (int*)&blockLen)) {
		perror("EVP_SealFinal");
        return;
    }
    encMsgLen += blockLen;
	
    EVP_CIPHER_CTX_cleanup(rsaEncryptCtx);
	
	*enc_msg = encMsg;
	*enc_msg_length = encMsgLen;
	*iv = iv_data;
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
