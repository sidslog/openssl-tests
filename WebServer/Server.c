//
//  Server.c
//  WebServer
//
//  Created by sidslog on 02.03.14.
//
//

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

#define READ_BUF_SIZE 64

void socketRead(int socket, char** buf, ssize_t* length) {
	char readBuf[READ_BUF_SIZE];
	ssize_t readCount;
	
	ssize_t allReadCount = 0;
	ssize_t bufSize = READ_BUF_SIZE;
	char *outBuf = (char *) malloc(READ_BUF_SIZE * sizeof(char));
	
	while ((readCount = recv(socket, readBuf, READ_BUF_SIZE, 0)) > 0) {
		printf("read from socket: %zd\n", readCount);
		if (readCount + allReadCount > bufSize) {
			bufSize += READ_BUF_SIZE;
			outBuf = realloc(outBuf, bufSize * sizeof(char));
		}
		memcpy(outBuf + allReadCount, readBuf, readCount);
		allReadCount += readCount;
		
		if (outBuf[allReadCount - 1] == '\n') {
			break;
		}
	}
	
	char *tmp = malloc(sizeof(char) * allReadCount);
	memcpy(tmp, outBuf, allReadCount);
	
	free(outBuf);
	
	*buf = tmp;
	*length = allReadCount;
	printf("read ended : %zd\n", allReadCount);
}

void dumpReadString(char * str, ssize_t length) {
	char buf2[length + 1];
	memcpy(buf2, str, length);
	buf2[length] = '\0';
	printf("socket read: %s", buf2);
}

void processSocket(int new_socket) {
	
	printf("start process socket\n");
	char *readStr = NULL;
	ssize_t readCount = 0;
	
	socketRead(new_socket, &readStr, &readCount);
	if (readCount > 0 && readStr) {
		dumpReadString(readStr, readCount);
	}
	
	free(readStr);
	
	char *msg = "123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf 123 sdfsdsf sdfsdfsdfsd fs dfsdfsdfsdf ";
	ssize_t sendRes = write(new_socket, msg, strlen(msg));
	
	printf("send done: %zd\n", sendRes);
	
	if (sendRes == -1) {
		perror("send");
		close(new_socket);
		return;
	}
	
	if (close(new_socket) == -1) {
		perror("close new_scket in child");
	}

}

int startServer(in_port_t port) {
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		perror("couldn't create socket");
		return 0;
	}
	
	struct sockaddr_in address;
	
	/* type of socket created in socket() */
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	
	
	/* 7000 is the port to use for connections */
	address.sin_port = port;
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
	pid_t pid = -1;
	int new_socket;
	for (;;) {
		printf("pid = %d\n", getpid());
		new_socket = accept(sock, (struct sockaddr *)&address, &addrlen);
		printf("client connected :%d\n", getpid());
		
		if (new_socket<0) {
			printf("pid in interrupt: %d\n", getpid());
			perror("Accept connection");
			close(new_socket);
			continue;
		}
		
		/* Create child process */
		switch(pid = fork()) {
			case -1:
				close(new_socket);
			case 0: {
				if (close(sock) == -1) {
					perror("close sock");
				}
				printf("forked process\n");
				processSocket(new_socket);
				goto end;
			}
			default:
				if (close(new_socket)== -1) {
					perror("close new_scket in parent");
				}
				printf("here2\n");
				continue;
		}
	}
	
	end:
	return 0;
}


