//
//  WideMouthFrog.h
//  OpenSSLTests
//
//  Created by sidslog on 10.03.14.
//
//

#ifndef OpenSSLTests_WideMouthFrog_h
#define OpenSSLTests_WideMouthFrog_h

#include "SecurePacket.h"
#include "SecureClient.h"

#pragma mark - Wide-Mouth Frog

void wmf_proto_example();

void wmf_alice_to_trent(SECURE_CLIENT *alice, SECURE_CLIENT *trent);
void wmf_trent(PACKET *packet, void *self);
void wmf_bob(PACKET *packet, void *self);

#endif
