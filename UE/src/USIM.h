/*
 * USIM.h

 */
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include "identifier.h"

#ifndef USIM_H_
#define USIM_H_

#define NID NID_X9_62_prime256v1
static sn_name_t sn_name_home = "5G:NTNUnet";
static unsigned char s_pubKey[65];
static unsigned char *s_Ksu = NULL;

static RSA *s_AF_rsa = NULL;

void initUSIM(supi_t *supi);
void get_SUCI(suci_t *suci);
int get_HomeNetworkPublicKey(char *servAddr);
int autnIsAccepted(uint8_t autn[16], uint8_t rand[16]);
void computeRES(uint8_t autn[16], uint8_t rand[16],uint8_t res[8], uint8_t ck[16],uint8_t ik[16]);
void derive_Kausf(sn_name_t *sn_name, uint8_t *rand,uint8_t *kausf);
void getECKey(EVP_PKEY *pkey, unsigned char * pubkey, size_t *pubkey_len);
unsigned char * getSharedKey(EVP_PKEY *pkey, unsigned char * peer_pubkey, size_t *secret_len);
unsigned char *getCT_UE_AF(unsigned char *a, size_t a1_len, size_t *len);
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
#endif /* USIM_H_ */


