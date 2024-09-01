/*
 *  sidf.c
 *
 *
 */

#include "sidf.h"
#include <stdio.h>
#include <math.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <string.h>
#include "genericFunctions.h"
#include "ffunction.h"

/*--- Global variables ---*/
static EVP_PKEY_CTX *pctx, *kctx;
static EVP_PKEY *pkey = NULL, *peerkey = NULL, *params = NULL;
static int ebene = 3;

unsigned char homeNetworkPublicKey[65];


const int hashmaxlen = 256;

/*--- Functions ---*/

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
    abort();
}

void sidf_init(){
#ifdef showmethod
	printm(ebene,"SIDF: sidf_init\n");
#endif
	/* Create the context for parameter generation */
	if(NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) handleErrors();

	/* Initialise the parameter generation */
	if(1 != EVP_PKEY_paramgen_init(pctx)) handleErrors();

	/* We're going to use the ANSI X9.62 Prime 256v1 curve */
	if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)) handleErrors();

	/* Create the parameter object params */
	if (!EVP_PKEY_paramgen(pctx, &params)) handleErrors();

	/* Create the context for the key generation */
	if(NULL == (kctx = EVP_PKEY_CTX_new(params, NULL))) handleErrors();

	/* Generate the key */
	if(1 != EVP_PKEY_keygen_init(kctx)) handleErrors();
	if (1 != EVP_PKEY_keygen(kctx, &pkey)) handleErrors();

	// Serialize Home Network Public Key
	EC_KEY* eckey = NULL;
	const EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	size_t size = 1000;
	unsigned char pubkey[size];
	unsigned char privatekey[size];
	size_t a;
	BN_CTX* ctx;
	ctx = BN_CTX_new();
	eckey = EVP_PKEY_get1_EC_KEY(pkey);
	const EC_POINT* ecpoint = EC_KEY_get0_public_key(eckey);
	a = EC_POINT_point2oct(ecgroup ,ecpoint ,EC_GROUP_get_point_conversion_form(ecgroup),pubkey,size,ctx);
	memcpy(homeNetworkPublicKey, pubkey,65);
	printf("Home Network Publickey[%lu]: ",a);
	for(int idx=0;idx<a;idx++){
		printf("%02x", homeNetworkPublicKey[idx]);
	}
	printf("\n");

}

unsigned char* getSharedSecret(size_t *secret_len, unsigned char* pubkey, size_t size_pubkey){
#ifdef showmethod
	printm(ebene,"SIDF: getSharedSecret\n");
#endif
#ifdef measurefct
	uint64_t a,b;
	a=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	unsigned char *secret;
	EVP_PKEY_CTX *ctx;

	EC_POINT* peerpoint;
	EC_KEY* peereckey;
	size_t secretLength;

	const EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

	peereckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	ecgroup = EC_KEY_get0_group(peereckey);
	peerpoint = EC_POINT_new(ecgroup);

	const unsigned char* buf = pubkey;
	int f=-5,c=-5,d=-5;

#ifdef test
	printf("Publickey[%lu]: ",size_pubkey);
	for(int idx=0;idx<size_pubkey;idx++){
		printf("%x", pubkey[idx]);
	}
	printf("\n");
#endif
	// f = EC_POINT_hex2point(ecgroup, buf, peerpoint, NULL);  
	//UE use EC_POINT_oct2point() func. It causes to caculate the wrong key, 
	// so UDM should use EC_POINT_oct2point() func.
	f = EC_POINT_oct2point(ecgroup, peerpoint, buf,65, NULL);
	c = EC_KEY_set_public_key(peereckey, peerpoint);
	peerkey = EVP_PKEY_new();
	d = EVP_PKEY_set1_EC_KEY(peerkey,peereckey);

	/* To serialize the public key:

	Pass the EVP_PKEY to EVP_PKEY_get1_EC_KEY() to get an EC_KEY.
	Pass the EC_KEY to EC_KEY_get0_public_key() to get an EC_POINT.
	Pass the EC_POINT to EC_POINT_point2oct() to get octets, which are just unsigned char *.
	 */


	if(NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL))) handleErrors();

	/* Initialise */
	if(1 != EVP_PKEY_derive_init(ctx)) handleErrors();

	/* Provide the peer public key */
	if(1 != EVP_PKEY_derive_set_peer(ctx, peerkey)) handleErrors();

	/* Determine buffer length for shared secret */
	if(1 != EVP_PKEY_derive(ctx, NULL, &secretLength)) handleErrors();

	/* Create the buffer */
	if(NULL == (secret = OPENSSL_malloc(secretLength))) handleErrors();

	/* Derive the shared secret */
	int e = EVP_PKEY_derive(ctx, secret, &secretLength);
	//if(1 != (EVP_PKEY_derive(ctx, secret, &secretLength))) handleErrors();
#ifdef test
	printf("a%d %s\n",e, secret);
	for(int i=0; i<secretLength;i++){
		printf("%X", secret[i]);
	}
	//if(1 != (e)) handleErrors();
	printf("a %d\n", secretLength);
#endif
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(peerkey);

	/* Never use a derived secret directly. Typically it is passed
	 * through some hash function to produce a key */
	*secret_len = secretLength;

	//TODO: sharedsecret doesn't work -> fixed secret
	/*for(int cnt=0; cnt<secretLength;cnt++){
		secret[cnt] = '0';
	}*/

#ifdef measurefct
	b=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",a);
	printf("B: %lu \n",b);
	printf("SharedSecret Duration %lu ns\n",b-a);
#endif
	return secret;
}

void kdf(unsigned char *sharedSecret, uint8_t sslen, size_t* keydatalen, char *sharedinfo, uint8_t silen, unsigned char* key){
	//SEC 1: Elliptic Curve Cryptography, 3.6.1
#ifdef showmethod
	printm(ebene,"SIDF: kdf\n");
#endif
#ifdef measurefct
	uint64_t a,b;
	a=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
#ifdef testb
	puts("shared:");
		for(int i=0; i<sslen;i++){
				printf("%X",sharedSecret[i]);
			}
		puts("");
#endif
	int hashlen = sslen + silen + 4;
	int i;
#ifdef testb
	printf("%d : %d\n",hashlen, hashmaxlen);
	printf("%d : %d\n",sslen, silen);
#endif

	if((hashlen) >= hashmaxlen){
		*key = "invalid";
		*keydatalen = strlen(key);
		return;
	}

	/*unsigned a =(unsigned)pow(2,32) - 1;
	unsigned b = hashlen * a;
	printf("keydatalen: %d, hashlen: %u, %u\n",*keydatalen, a,b);
	if(*keydatalen >= a){
		*key = "invalid";
		*keydatalen = strlen(key);
		return;
	}*/
	uint32_t counter = 0x00000001;

	for(i = 0; i<*keydatalen; i++){

		//printf("i: %d %d\n",i,sslen);
		unsigned char hashinput[hashlen], md[32]; //= malloc(hashlen);

		for(int i=0; i<sslen;i++){
			hashinput[i] = sharedSecret[i];
		}

		//memcpy(hashinput, sharedSecret, sslen);
		//printf("hashinput: %s\n", hashinput);
		unsigned char tmp[5];
		sprintf(tmp, "%04x", counter);
		// strncat(hashinput, tmp, 4); //here is a problem, hashinput is not a null-terminal string
		memcpy(hashinput + sslen, tmp, 4);


		//strncat(hashinput, sharedinfo, silen);

		//printf("hashinput: %s\n", hashinput);

		SHA256(hashinput,sizeof(hashinput),md);

		key[i] = md[0];

		counter++;

		//free(hashinput);
	}

#ifdef testb
	printf("Keydatalen: %u\n", *keydatalen);
	for(i=0; i<*keydatalen;i++){
		printf("%2x",key[i]);
	}
	puts("\n");
#endif

#ifdef measurefct
	b=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",a);
	printf("B: %lu \n",b);
	printf("kdf Duration %lu ns\n",b-a);
#endif
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
#ifdef showmethod
	printm(ebene,"SIDF: encrypt\n");
#endif
#ifdef measurefct
	uint64_t a,b;
	a=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
#ifdef measurefct
	b=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",a);
	printf("B: %lu \n",b);
	printf("encrypt Duration %lu ns\n",b-a);
#endif
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
#ifdef showmethod
	printm(ebene,"SIDF: decrypt\n");
#endif
#ifdef measurefct
	uint64_t a,b;
	a=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	EVP_CIPHER_CTX *ctx;

    int len = 0;

    int plaintext_len = 0;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

#ifdef measurefct
	b=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",a);
	printf("B: %lu \n",b);
	printf("decrypt Duration %lu ns\n",b-a);
#endif
    return plaintext_len;
}


int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, int iv_len, unsigned char *ciphertext,
                unsigned char *tag, int tag_len)
{
#ifdef showmethod
	printm(ebene,"SIDF: gcm_encrypt\n");
#endif
#ifdef measurefct
	uint64_t a,b;
	a=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation. */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
		handleErrors();
	/*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
		handleErrors();

	/* Initialise key and IV */
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

	/* Get the tag */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
#ifdef measurefct
	b=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",a);
	printf("B: %lu \n",b);
	printf("gcm_encrypt Duration %lu ns\n",b-a);
#endif
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *tag, int tag_len, unsigned char *key, unsigned char *iv,
                int iv_len, unsigned char *plaintext)
{
#ifdef showmethod
	printm(ebene,"SIDF: gcm_decrypt\n");
#endif
#ifdef measurefct
	uint64_t a,b;
	a=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	EVP_CIPHER_CTX *ctx;

    int len = 0;

    int plaintext_len = 0;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrors();
	
	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag))
        handleErrors();

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0)
    {
        /* Success */
        plaintext_len += len;
    }
    else
    {
        /* Verify failed */
        handleErrors();
    }

#ifdef measurefct
	b=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",a);
	printf("B: %lu \n",b);
	printf("gcm_decrypt Duration %lu ns\n",b-a);
#endif
    return plaintext_len;
}


/*
EVP_PKEY *pkey: must use EVP_PKEY_new() to allocate an empty EVP_PKEY structure before call
unsigned char * pubkey: store public key(in HEX format) after call, cannot be NULL
size_t *pubkey_len: store public key size
*/

void getECKey(EVP_PKEY *AF_pkey, unsigned char * AF_pubkey, size_t *AF_pubkey_len) {

    EVP_PKEY_CTX *ec_kctx;
    EVP_PKEY_CTX *ec_pctx;
    EVP_PKEY *ec_peerkey = NULL, *ec_params = NULL;
    EC_KEY* ec_key  = NULL;
    const EC_POINT* ec_point = NULL;
    BN_CTX* bn_ctx;
    EC_GROUP* ec_group = NULL;

    /* Create the context for parameter generation */
	if(NULL == (ec_pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) handleErrors();
	/* Initialise the parameter generation */
	if(1 != EVP_PKEY_paramgen_init(ec_pctx)) handleErrors();

	/* We're going to use the ANSI X9.62 Prime 256v1 curve */
	if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ec_pctx, NID)) handleErrors();
	/* Create the parameter object params */
	if (!EVP_PKEY_paramgen(ec_pctx, &ec_params)) handleErrors();
	/* Create the context for the key generation */
	if(NULL == (ec_kctx = EVP_PKEY_CTX_new(ec_params, NULL))) handleErrors();
	/* Generate the key */
	if(1 != EVP_PKEY_keygen_init(ec_kctx)) handleErrors();
	if (1 != EVP_PKEY_keygen(ec_kctx, &AF_pkey)) handleErrors();
    // if (1 != EVP_PKEY_generate(kctx, &pkey)) handleErrors();

    if (NULL == (ec_key = EVP_PKEY_get1_EC_KEY(AF_pkey))) handleErrors();

	if (NULL == (ec_point = EC_KEY_get0_public_key(ec_key))) handleErrors();

    if (NULL == (ec_group = EC_GROUP_new_by_curve_name(NID) )) handleErrors();

    if (NULL == (bn_ctx = BN_CTX_new())) handleErrors();

    (*AF_pubkey_len) = EC_POINT_point2oct(ec_group ,ec_point,
			EC_GROUP_get_point_conversion_form(ec_group),AF_pubkey,1024,bn_ctx);
    if((*AF_pubkey_len) <= 0)
    {
        handleErrors();
    }
#ifdef DebugAkmaInfo
    printf("sidf print pubkey(%d): ", (*AF_pubkey_len));
    for (int i = 0; i < (*AF_pubkey_len); i++)
    {
        printf("%02x", AF_pubkey[i]);
    }
    printf("\n");
#endif
    BN_CTX_free(bn_ctx);
    EC_POINT_free(ec_point);
    EC_KEY_free(ec_key);
    EVP_PKEY_free(ec_params);
    EVP_PKEY_free(ec_peerkey);
    EVP_PKEY_CTX_free(ec_pctx);
    EVP_PKEY_CTX_free(ec_kctx);
}


/*
EVP_PKEY *pkey: must use getECKey()  before call
unsigned char * peer_pubkey: the public key which peer generate
size_t *secret_len: store shared key size
return value: shared key, this function will allocate the memory for it.
*/
unsigned char * getSharedKey(EVP_PKEY *pkey, unsigned char * peer_pubkey, size_t *secret_len) {

    EVP_PKEY_CTX *ctx;
	EC_POINT* peer_point;
	EC_KEY* peer_eckey;

	EC_GROUP* peer_ecgroup;
    EVP_PKEY *peer_pkey;

    unsigned char *sharedSecret;
    
    // ecgroup = EC_GROUP_new_by_curve_name(NID);
    if(NULL == (peer_eckey = EC_KEY_new_by_curve_name(NID))) handleErrors();

	peer_ecgroup = EC_KEY_get0_group(peer_eckey);

    if(NULL == (peer_point = EC_POINT_new(peer_ecgroup) )) handleErrors();

    if( 1 != EC_POINT_oct2point(peer_ecgroup, peer_point, peer_pubkey,65, NULL)) handleErrors();

	if( 1 != EC_KEY_set_public_key(peer_eckey, peer_point) ) handleErrors();

	if(NULL == (peer_pkey = EVP_PKEY_new())) handleErrors();

	if( 1 != EVP_PKEY_set1_EC_KEY(peer_pkey,peer_eckey) ) handleErrors();
    /* To serialize the public key:

	Pass the EVP_PKEY to EVP_PKEY_get1_EC_KEY() to get an EC_KEY.
	Pass the EC_KEY to EC_KEY_get0_public_key() to get an EC_POINT.
	Pass the EC_POINT to EC_POINT_point2oct() to get octets, which are just unsigned char *.
	 */
	if(NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL))) handleErrors();

	/* Initialise */
	if(1 != EVP_PKEY_derive_init(ctx)) handleErrors();

	/* Provide the peer public key */
	if(1 != EVP_PKEY_derive_set_peer(ctx, peer_pkey)) handleErrors();


	/* Determine buffer length for shared secret */
	// if(1 != EVP_PKEY_derive(ctx, NULL, secretLength)) handleErrors();
    EVP_PKEY_derive(ctx, NULL, secret_len);


	/* Create the buffer */
	if(NULL == (sharedSecret = OPENSSL_malloc(*secret_len))) handleErrors();


	/* Derive the shared secret */
	if(1 != EVP_PKEY_derive(ctx, sharedSecret, secret_len)) handleErrors();


    EVP_PKEY_free(peer_pkey);
    EC_GROUP_free(peer_ecgroup);
    // EC_KEY_free(peer_eckey);   // peer_eckey can not free, program will corrupt
    EC_POINT_free(peer_point);
    // EVP_PKEY_CTX_free(ctx);  // ctx can not free, program will corrupt

    return sharedSecret;
    

}