//
//  WideMouthFrog.c
//  OpenSSLTests
//
//  Created by sidslog on 10.03.14.
//
//

#include <stdio.h>
#include <time.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include "WideMouthFrog.h"
#include "OpenSSLHelper.h"

void wmf_proto_example() {
	SESSION_KEY public_key;
	SESSION_KEY private_key;
	
	keypair_gen(&public_key, &private_key);
	
	SESSION_KEY trent_bob_key = session_key_create(128);
	
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
	trent->func = wmf_trent;
	
	trent->context = malloc(sizeof(CLIENT_CONTEXT));
	trent->context->private_key = &private_key;
	trent->context->session_key = &trent_bob_key;
	
	SECURE_CLIENT *bob = malloc(sizeof(SECURE_CLIENT));
	bob->label = "Bob";
	bob->port = htons(7009);
	bob->stopped = malloc(sizeof(int));
	bob->func = wmf_bob;
	
	bob->context = malloc(sizeof(CLIENT_CONTEXT));
	bob->context->session_key = &trent_bob_key;
	
	
	clients = malloc(3 * sizeof(SECURE_CLIENT *));
	clients[0] = alice;
	clients[1] = trent;
	clients[2] = bob;
	
	clients_count = 3;
	
	client_start(alice);
	client_start(trent);
	client_start(bob);
	
	wmf_alice_to_trent(alice, trent);
	
	sleep(10);
	
	client_stop(alice);
	client_stop(trent);
	client_stop(bob);

}

void wmf_alice_to_trent(SECURE_CLIENT *alice, SECURE_CLIENT *trent) {
	PACKET *packet = packet_create(COMMAND_WMF_1);
	
	TIMESTAMP timestamp = time(NULL);
	CLIENT_NAME bob_name = "Bob";
	SESSION_KEY key = session_key_create(128);
	
	printf("Alice generated sessionKey:\n");
	session_key_dump(&key);
	
	packet_add_arg(packet, (uint32_t)strlen(alice->label), (BYTE_PTR )alice->label);
	
	
	BYTE_PTR buf = malloc(sizeof(uint32_t));
	uint32_t buf_length = 0;
	
	uint32_t bob_name_length = (uint32_t) strlen(bob_name);
	uint32_t count = 3;
	
	memcpy(buf, &count, sizeof(uint32_t));
	buf_length = sizeof(uint32_t);
	
	command_data_add_arg(&buf, &buf_length, (BYTE_PTR)&timestamp, sizeof(uint32_t));
	command_data_add_arg(&buf, &buf_length, (BYTE_PTR)bob_name, bob_name_length);
	command_data_add_arg(&buf, &buf_length, key.data, (uint32_t)key.length);
	
	
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

void wmf_trent(PACKET *packet, void *self) {
	if (packet->command == COMMAND_WMF_1) {
		SECURE_CLIENT *client = (SECURE_CLIENT *) self;
		SESSION_KEY *key = client->context->private_key;
		
		char *alice_name = (char *) packet->args[0]->arg;
		
		
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
		
		PACKET_ARG **values;
		int value_length = command_args_from_data(out, out_length, &values);
		if (value_length == 3) {
			TIMESTAMP timestamp = time(NULL);
			char *bob_name = (char *) values[1]->arg;
			printf("trent received bob name: %s\n", bob_name);
			
			BYTE_PTR session_key = values[2]->arg;
			uint32_t session_key_length = values[2]->length;
			
			SECURE_CLIENT *bob = client_by_label(bob_name);
			
			BYTE_PTR buf = malloc(sizeof(uint32_t));
			uint32_t buf_length = 0;
			
			uint32_t alice_name_length = (uint32_t) strlen(alice_name);
			uint32_t count = 3;
			
			memcpy(buf, &count, sizeof(uint32_t));
			buf_length = sizeof(uint32_t);
			
			command_data_add_arg(&buf, &buf_length, (BYTE_PTR)&timestamp, sizeof(uint32_t));
			command_data_add_arg(&buf, &buf_length, (BYTE_PTR)alice_name, alice_name_length);
			command_data_add_arg(&buf, &buf_length, session_key, session_key_length);
			
			BYTE_PTR enc;
			uint32_t enc_length;
			
			data_encode_aes(buf, buf_length, client->context->session_key, &enc, &enc_length);
			
			PACKET *p = packet_create(COMMAND_WMF_2);
			packet_add_arg(p, enc_length, enc);
			
			int sock = socket_connect_to_client(bob);
			packet_write(sock, p);
			
			packet_free(p);
			free(buf);
			
		} else {
			perror("wrong arg count");
		}
		
		free(out);
		free(values);
	} else {
		perror("unknown command");
	}
	
}

void wmf_bob(PACKET *packet, void *self) {
	if (packet->command == COMMAND_WMF_2) {
		SECURE_CLIENT *client = (SECURE_CLIENT *) self;
		
		BYTE_PTR msg = packet->args[0]->arg;
		uint32_t msg_length = packet->args[0]->length;
		
		BYTE_PTR out;
		uint32_t out_length;
		
		data_decode_aes(msg, msg_length, client->context->session_key, &out, &out_length);
		
		printf("decoded data:\n");
		bytes_dump(out, out_length);
		
		PACKET_ARG **values;
		int value_length = command_args_from_data(out, out_length, &values);
		if (value_length == 3) {
			
			char *alice_name = (char *) values[1]->arg;
			BYTE_PTR session_key = values[2]->arg;
			uint32_t session_key_length = values[2]->length;
			
			printf("bob received!\n");
			printf("alice name:%s\n", alice_name);
			printf("session key\n");
			
			bytes_dump(session_key, session_key_length);
			
		} else {
			perror("wrong arg count");
		}
		
		free(out);
		free(values);
	} else {
		perror("unknown command");
	}
	
}