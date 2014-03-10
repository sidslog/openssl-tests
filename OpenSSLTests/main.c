//
//  main.c
//  OpenSSLTests
//
//  Created by sidslog on 02.03.14.
//
//

#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <time.h>
#include "SecureClient.h"
#include "OpenSSLHelper.h"
#include "WideMouthFrog.h"

int main(int argc, const char * argv[])
{

	// insert code here...
	wmf_proto_example();
    return 0;
}

