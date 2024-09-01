/*
 * sidf.h
 *
 */

#include <stdlib.h>
#ifndef SIDF_H_
#define SIDF_H_
#include "defs.h"
#include <stdint.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>

#define NID NID_X9_62_prime256v1
#define IV_LEN  12    /*  96 bits */
#define TAG_SIZE 2
static const uint8_t iv[IV_LEN]           = { 0 };

void sidf_init();
unsigned char* getSharedSecret(size_t *secret_len, unsigned char* pubkey, size_t size_pubkey);
void kdf(unsigned char *sharedSecret, uint8_t sslen, size_t* keydatalen, char *sharedinfo, uint8_t silen, unsigned char* key);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);
int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, int iv_len, unsigned char *ciphertext,
                unsigned char *tag, int tag_len);
int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *tag, int tag_len, unsigned char *key, unsigned char *iv,
                int iv_len, unsigned char *plaintext);
void getECKey(EVP_PKEY *pkey, unsigned char * pubkey, size_t *pubkey_len);
unsigned char * getSharedKey(EVP_PKEY *pkey, unsigned char * peer_pubkey, size_t *secret_len);
#endif /* SIDF_H_ */



