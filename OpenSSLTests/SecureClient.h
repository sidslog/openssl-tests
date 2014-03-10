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

int client_start(SECURE_CLIENT *client);
void client_stop(SECURE_CLIENT *client);

#pragma mark - Wide-Mouth Frog

void wmf_alice_to_trent(SECURE_CLIENT *alice, SECURE_CLIENT *trent, TIMESTAMP time, CLIENT_NAME bob_name, SESSION_KEY key);

#endif
