//
//  OpenSSLHelper.c
//  OpenSSLTests
//
//  Created by sidslog on 10.03.14.
//
//

#include <stdio.h>

#include "SecurePacket.h"

#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/rand.h"
#include "openssl/bn.h"
#include "openssl/evp.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

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
		goto end;
    }
	
	*decMsg = (unsigned char*)malloc(encMsgLen + ivl);
	
    if(!EVP_OpenInit(rsaDecryptCtx, EVP_aes_128_cbc(), ek, (int)ekl, iv, pkey)) {
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
	
end:
    EVP_CIPHER_CTX_cleanup(rsaDecryptCtx);
	free(rsaDecryptCtx);
	*dec_msg_length	= (uint32_t) decLen;
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
    BYTE_PTR encMsg = malloc(data_length + EVP_MAX_IV_LENGTH);
    BYTE_PTR iv_data = (unsigned char*)malloc(EVP_MAX_IV_LENGTH);
    if(*ek == NULL || iv_data == NULL) {
		perror("malloc error");
		goto end;
	};
	
    if(encMsg == NULL) {
		perror("malloc2 error");
		goto end;
	}
	
    if(!EVP_SealInit(rsaEncryptCtx, EVP_aes_128_cbc(), ek, (int*) ekl, iv_data, &pkey, 1)) {
		perror("EVP_SealInit");
        goto end;
    }
	
    if(!EVP_SealUpdate(rsaEncryptCtx, encMsg + encMsgLen, (int*)&blockLen, (const unsigned char*)data, (int)data_length)) {
		perror("EVP_SealUpdate");
        goto end;
    }
    encMsgLen += blockLen;
	
    if(!EVP_SealFinal(rsaEncryptCtx, encMsg + encMsgLen, (int*)&blockLen)) {
		perror("EVP_SealFinal");
        return;
    }
    encMsgLen += blockLen;
	
    EVP_CIPHER_CTX_cleanup(rsaEncryptCtx);
end:
	free(rsaEncryptCtx);
	*enc_msg = encMsg;
	*enc_msg_length = encMsgLen;
	*iv = iv_data;
}

void data_encode_aes(BYTE_PTR data, ssize_t data_length, SESSION_KEY *key, BYTE_PTR *enc_msg, uint32_t *enc_msg_length) {
	EVP_CIPHER_CTX *aesEncryptCtx;
	aesEncryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(aesEncryptCtx);
	
	uint32_t encMsgLen = 0;
    int blockLen  = 0;
	

	if (!EVP_EncryptInit(aesEncryptCtx, EVP_aes_128_cbc(), key->data, NULL)) {
		perror("EVP_EncryptInit");
		goto end;
	}
	
	BYTE_PTR out = malloc(data_length + EVP_CIPHER_CTX_block_size(aesEncryptCtx) - 1);
	
	if (!EVP_EncryptUpdate(aesEncryptCtx, out, &blockLen, data, (int) data_length)) {
		perror("EVP_EncryptInit");
		free(out);
		goto end;
	}
	
	encMsgLen += blockLen;
	
	if (!EVP_EncryptFinal(aesEncryptCtx, out + encMsgLen, &blockLen)) {
		perror("EVP_EncryptInit");
		free(out);
		goto end;
	}
	
	EVP_CIPHER_CTX_cleanup(aesEncryptCtx);
	
	*enc_msg = out;
	encMsgLen += blockLen;
	*enc_msg_length = encMsgLen;

end:
	free(aesEncryptCtx);
}


void data_decode_aes(BYTE_PTR data, ssize_t data_length, SESSION_KEY *key, BYTE_PTR *enc_msg, uint32_t *enc_msg_length) {
	EVP_CIPHER_CTX *aesEncryptCtx;
	aesEncryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(aesEncryptCtx);
	
	uint32_t encMsgLen = 0;
    int blockLen  = 0;
	
	
	if (!EVP_DecryptInit(aesEncryptCtx, EVP_aes_128_cbc(), key->data, NULL)) {
		perror("EVP_EncryptInit");
		goto end;
	}
	
	BYTE_PTR out = malloc(data_length + EVP_CIPHER_CTX_block_size(aesEncryptCtx));

	if (!EVP_DecryptUpdate(aesEncryptCtx, out, &blockLen, data, (int) data_length)) {
		perror("EVP_EncryptInit");
		free(out);
		goto end;
	}
	
	encMsgLen += blockLen;
	
	if (!EVP_DecryptFinal(aesEncryptCtx, out + encMsgLen, &blockLen)) {
		perror("EVP_EncryptInit");
		free(out);
		goto end;
	}

	EVP_CIPHER_CTX_cleanup(aesEncryptCtx);

	*enc_msg = out;
	encMsgLen += blockLen;
	*enc_msg_length = encMsgLen;
	
end:
	free(aesEncryptCtx);
}


#pragma clang diagnostic pop
