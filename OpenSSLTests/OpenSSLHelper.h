//
//  OpenSSLHelper.h
//  OpenSSLTests
//
//  Created by sidslog on 10.03.14.
//
//

#ifndef OpenSSLTests_OpenSSLHelper_h
#define OpenSSLTests_OpenSSLHelper_h

#include "SecurePacket.h"

void session_key_dump(SESSION_KEY *key);
void keypair_gen(SESSION_KEY *public_key, SESSION_KEY *private_key);
SESSION_KEY session_key_create(int length);
void data_decode(BYTE_PTR encMsg, uint32_t encMsgLen, SESSION_KEY *key, BYTE_PTR iv, size_t ivl, BYTE_PTR ek, uint32_t ekl, BYTE_PTR *decMsg, uint32_t *dec_msg_length);
void data_encode(BYTE_PTR data, ssize_t data_length, SESSION_KEY *public_key, BYTE_PTR *enc_msg, uint32_t *enc_msg_length, BYTE_PTR *iv, uint32_t *ivl, BYTE_PTR *ek, uint32_t *ekl);

#endif
