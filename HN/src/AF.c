#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <time.h>
#include <unistd.h>

#include "AF.h"
#include "ffunction.h"
#include "genericFunctions.h"
#include "defs.h"
#include "sidf.h"

#define AF_SV_PORT 50002
#define AF_CL_PORT 50003
#define SEAF_SV_PORT 50001

#define BUFSIZE 2048

#define RSA_KEY_LENGTH 1024
// #define Res_AAnF_Sign_Len 128

static int ebene = 0;
static a_kid_t g_a_kid;
static af_id_t g_af_id;
static k_af_t g_k_af;
static struct timeval g_k_af_exp;
static supi_t g_supi;
static EVP_PKEY *s_pkey_AF_UE;

extern size_t s_RSA_pubkey_len; // Length of public key
char *PK_AF = NULL;             // RSA Public key
size_t PK_AF_len;               // Length of public key

unsigned char U[65]; // UE public key
static EVP_PKEY *s_RSA_pkey;

// ECDSA key, use to sign RES_AF, ECIES use the same key
static EVP_PKEY *s_AF_ECDSA_pkey;
char *AF_ECDSA_Pubkey = NULL; // Public key
size_t AF_ECDSA_Pubkey_len;   // Length of public key

char *AF_ECIES_Pubkey = NULL; // Public key
size_t AF_ECIES_Pubkey_len;   // Length of public key

char *UE_ECIES_Pubkey = NULL; // Public key
size_t UE_ECIES_Pubkey_len;   // Length of public key

// ECIES shared Key, use to decrypt CT_UE_AF
char AF_UE_ECIES_Shared_Secret_Key[128]; 
size_t AF_UE_ECIES_Shared_Secret_Key_len = 128;   

// static unsigned char g_Res_AAnF_Sign[Res_AAnF_Sign_Len];

// static unsigned char g_Res_AAnF[1024];
// static int g_Res_AAnF_len;

void Application_Session_Establishment_Request_AF(a_kid_t *a_kid)
{
#ifdef showAKMAmethod
    printf("AKMA step 6 (UE-->AF) Application_Session_Establishment_Request_AF(A-KID) receive\n");
#endif
}

void Naanf_AKMA_ApplicationKey_GetRequest_AF(a_kid_t *a_kid, af_id_t *af_id,
                                             unsigned char *enc_CT_UE_AAnF, size_t enc_CT_UE_AAnF_len, unsigned char *CT_UE_AAnF_TAG,
                                             unsigned char *CT_AAnF_UE, unsigned int *p_CT_AAnF_UE_Len, unsigned char *CT_AAnF_UE_TAG)
{
#ifdef showAKMAmethod
    printf("AKMA step 7 (AF-->AAnF) Naanf_AKMA_ApplicationKey_GetRequest_AF(A-KID, AF_ID) send \n");
#endif

    // send msg to AAnF
    // Variable declaration
    struct sockaddr_in seaf_clAddr;
    struct sockaddr_in seaf_seafAddr;
    socklen_t seaf_addrlen = sizeof(seaf_seafAddr);
    int seaf_cl, seaf_recvlen;
    int seaf_slen = sizeof(seaf_seafAddr);
    unsigned char seaf_buf[BUFSIZE];
    unsigned char seaf_recev_buf[BUFSIZE];
    char *seaf_server = "127.0.0.1";

    // Set up client
    if ((seaf_cl = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("cannot create socket");
        exit(1);
    }
    memset((char *)&seaf_clAddr, 0, sizeof(seaf_clAddr));
    seaf_clAddr.sin_family = AF_INET;
    seaf_clAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    seaf_clAddr.sin_port = htons(AF_CL_PORT);
    if (bind(seaf_cl, (struct sockaddr *)&seaf_clAddr, sizeof(seaf_clAddr)) < 0)
    {
        perror("AF CL Bind failed");
        close(seaf_cl);
        return 0;
    }

    memset((char *)&seaf_seafAddr, 0, sizeof(seaf_seafAddr));
    seaf_seafAddr.sin_family = AF_INET;
    seaf_seafAddr.sin_port = htons(SEAF_SV_PORT);
    if (inet_aton(seaf_server, &seaf_seafAddr.sin_addr) == 0)
    {
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }

#ifdef measureAKMAfct
    uint64_t y, z;
    y = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
    memset(seaf_buf, 0x00, sizeof(seaf_buf));
    char *request = "AKMAKeyRequest"; // Application Session Establishment Requsest(A-KID)

    /* seaf_buf = "AKMAKeyRequest" + a_kid + af_id +
        CT_UE_AAnF_Len(4 bytes) + CT_UE_AAnF + CT_UE_AAnF_TAG(2 bytes)
        */
    int seaf_len_tmp = 0;
    memcpy(seaf_buf + seaf_len_tmp, request, strlen(request));
    seaf_len_tmp += strlen(request);

    memcpy(seaf_buf + seaf_len_tmp, (a_kid->username).rid.rid, sizeof((a_kid->username).rid.rid));
    seaf_len_tmp += sizeof((a_kid->username).rid.rid);

    memcpy(seaf_buf + seaf_len_tmp, (a_kid->username).a_tid, sizeof((a_kid->username).a_tid));
    seaf_len_tmp += sizeof((a_kid->username).a_tid);

    memcpy(seaf_buf + seaf_len_tmp, a_kid->at, sizeof(a_kid->at));
    seaf_len_tmp += sizeof(a_kid->at);

    memcpy(seaf_buf + seaf_len_tmp, a_kid->realm, sizeof(a_kid->realm));
    seaf_len_tmp += sizeof(a_kid->realm);

    memcpy(seaf_buf + seaf_len_tmp, af_id->fqdn, sizeof(af_id->fqdn));
    seaf_len_tmp += sizeof(af_id->fqdn);

    memcpy(seaf_buf + seaf_len_tmp, af_id->uaid, sizeof(af_id->uaid));
    seaf_len_tmp += sizeof(af_id->uaid);
#ifdef measureAKMAfct
    z = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
    printf("AF step 7 Duration %lu ns\n", z - y);
#endif

#ifdef measureAKMAfct
    uint64_t y2, z2;
    y2 = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

    sprintf(seaf_buf + seaf_len_tmp, "%04d", enc_CT_UE_AAnF_len);
    seaf_len_tmp += 4;

    memcpy(seaf_buf + seaf_len_tmp, enc_CT_UE_AAnF, enc_CT_UE_AAnF_len);
    seaf_len_tmp += enc_CT_UE_AAnF_len;

    memcpy(seaf_buf + seaf_len_tmp, CT_UE_AAnF_TAG, TAG_SIZE);
    seaf_len_tmp += TAG_SIZE;

#ifdef measureAKMAfct
    z2 = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
    printf("AF step 7 akma+ add Duration %lu ns\n", z2 - y2);
#endif

#ifdef CommCosts
    printf("AKMA step 7 (AF-->AAnF) AF send message to AAnF(%d bytes)\n", seaf_len_tmp);
#ifdef DebugAkmaInfo
    for (int i = 0; i < seaf_len_tmp; i++)
    {
        printf("%02x", seaf_buf[i]);
    }
    printf("\n");
#endif
#endif

    if (sendto(seaf_cl, seaf_buf, seaf_len_tmp, 0, (struct sockaddr *)&seaf_seafAddr, seaf_slen) == -1)
    {
        perror("sendto");
        exit(1);
    }

    memset(&g_k_af, 0x00, sizeof(g_k_af));
    memset(&g_k_af_exp, 0x00, sizeof(g_k_af_exp));
    memset(&g_supi, 0x00, sizeof(g_supi));
    int offset = 0;
    // seaf_recev_buf = k_af_t + timeval + CT_AAnF_UE_Len(4 bytes) + CT_AAnF_UE + CT_AAnF_UE_TAG(2 bytes)
    seaf_recvlen = recvfrom(seaf_cl, seaf_recev_buf, BUFSIZE, 0, (struct sockaddr *)&seaf_seafAddr, &seaf_slen);

#ifdef CommCosts
    printf("AKMA step 13 (AAnF-->AF) AF receive message from AAnF(%d bytes)\n", seaf_recvlen);
#ifdef DebugAkmaInfo
    if (seaf_recvlen >= 0)
    {
        for (int i = 0; i < seaf_recvlen; i++)
        {
            printf("%02x", seaf_recev_buf[i]);
        }
        printf("\n");
    }
#endif
#endif

    int total_len = sizeof(k_af_t) + sizeof(struct timeval) + 4 + TAG_SIZE;
    if (seaf_recvlen < total_len)
    {
        perror("receive error, length is not enough");
        exit(1);
    }
#ifdef measureAKMAfct
    uint64_t y1, z1;
    y1 = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
    if (seaf_recvlen >= total_len)
    {
        // seaf_recev_buf = k_af_t + timeval + CT_AAnF_UE_Len(4 Bytes) + CT_AAnF_UE(2 Bytes)
        offset = 0;
        memcpy(g_k_af.k_af, seaf_recev_buf + offset, sizeof(g_k_af.k_af));
        offset += sizeof(g_k_af.k_af);

        memcpy(&g_k_af_exp, seaf_recev_buf + offset, sizeof(struct timeval));
        offset += sizeof(struct timeval);

        // memcpy(g_supi.mcc_mnc, seaf_recev_buf + offset, sizeof(g_supi.mcc_mnc));
        // offset += sizeof(g_supi.mcc_mnc);

        // memcpy(g_supi.msin, seaf_recev_buf + offset, sizeof(g_supi.msin));
        // offset += sizeof(g_supi.msin);
#ifdef measureAKMAfct
        z1 = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
        printf("AF step 13 Duration %lu ns\n", z1 - y1);
#endif
#ifdef measureAKMAfct
        uint64_t y2, z2;
        y2 = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
        // unsigned char str_Res_AAnF_len[5];
        // memset(str_Res_AAnF_len, 0x00, sizeof(str_Res_AAnF_len));
        // memcpy(str_Res_AAnF_len, seaf_recev_buf + offset, 4);
        // offset += 4;
        // g_Res_AAnF_len = atoi(str_Res_AAnF_len);

        // memcpy(g_Res_AAnF, seaf_recev_buf + offset, g_Res_AAnF_len);
        // offset += g_Res_AAnF_len;

        // memcpy(g_Res_AAnF_Sign, seaf_recev_buf + offset, Res_AAnF_Sign_Len);
        // offset += Res_AAnF_Sign_Len;
        unsigned char str_CT_AAnF_UE_Len[5];
        memset(str_CT_AAnF_UE_Len, 0x00, sizeof(str_CT_AAnF_UE_Len));
        memcpy(str_CT_AAnF_UE_Len, seaf_recev_buf + offset, 4);
        offset += 4;
        (*p_CT_AAnF_UE_Len) = atoi(str_CT_AAnF_UE_Len);

        memcpy(CT_AAnF_UE, seaf_recev_buf + offset, (*p_CT_AAnF_UE_Len));
        offset += (*p_CT_AAnF_UE_Len);

        memcpy(CT_AAnF_UE_TAG, seaf_recev_buf + offset, TAG_SIZE);
        offset += TAG_SIZE;
    }
#ifdef measureAKMAfct
    z2 = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
    printf("AF step 13 get CT_AAnF_UE Duration %lu ns\n", z2 - y2);
#endif
    Naanf_AKMA_ApplicationKey_GetResponse_AF(&g_k_af, &g_k_af_exp, &g_supi);
}

void Naanf_AKMA_ApplicationKey_GetResponse_AF(k_af_t *k_af, struct timeval *k_af_exp, supi_t *supi)
{
#ifdef showAKMAmethod
    printf("AKMA step 13 (AAnF-->AF) Naanf_AKMA_ApplicationKey_GetResponse_AF(k_af, k_af_exp, supi_t) receive \n");
#endif
}

void Application_Session_Establishment_Response_AF()
{
#ifdef showAKMAmethod
    printf("AKMA step 14 (AF-->UE) Application_Session_Establishment_Response_AF send\n");
#endif
    // #ifdef measureAKMAfct
    //     uint64_t y, z;
    //     y = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
    // #endif

    // #ifdef measureAKMAfct
    //     z = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
    //     // printf("A: %lu \n",y);
    //     // printf("B: %lu \n",z);
    //     printf("AF step 14 Duration %lu ns\n", z - y);
    // #endif
}

static void Parse2AKID(unsigned char *msg, int len, a_kid_t *a_kid)
{

    // printf("\nAF Parse2AKID get MSG:");
    // for(int i=0; i< len;i++){
    // 	printf("%02x", msg[i]);
    // }
    // printf("\n");
    if (len < sizeof(a_kid_t))
    {
        perror("Parse2AKID");
        exit(1);
    }

    int offset = 0;

    memcpy((a_kid->username).rid.rid, msg + offset, sizeof((a_kid->username).rid.rid));
    offset += sizeof((a_kid->username).rid.rid);

    memcpy((a_kid->username).a_tid, msg + offset, sizeof((a_kid->username).a_tid));
    offset += sizeof((a_kid->username).a_tid);

    memcpy(a_kid->at, msg + offset, sizeof(a_kid->at));
    offset += sizeof(a_kid->at);

    memcpy(a_kid->realm, msg + offset, sizeof(a_kid->realm));
    offset += sizeof(a_kid->realm);

#ifdef DebugAkmaInfo
    print_akid(a_kid);
#endif
}

/*
generate RSA key

store public key in s_RSA_PK_AF;
store EVP_PKEY in s_RSA_pkey
*/
void generateRSAKey2()
{
#ifdef showAKMAmethod
    printf("AF generateRSAKey2 \n");
#endif
#ifdef DebugAkmaInfo
    printf("Generating RSA (%d bits) AF_keypair...", RSA_KEY_LENGTH);
#endif
    int modulus_bits = 1024;
    const uint32_t exponent = 0x10001;

    EVP_PKEY_CTX *rsa_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (rsa_ctx == NULL)
    {
        handleErrors();
    }

    if (EVP_PKEY_keygen_init(rsa_ctx) <= 0)
    {
        handleErrors();
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(rsa_ctx, modulus_bits) <= 0)
    {
        handleErrors();
    }

    BIGNUM *exponent_bn = BN_new();
    BN_set_word(exponent_bn, exponent);
    if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(rsa_ctx, exponent_bn) <= 0)
    {
        handleErrors();
    }

    if (EVP_PKEY_keygen(rsa_ctx, &s_RSA_pkey) != 1)
    {
        handleErrors();
    }

    // export public key to anyone
    BIO *PK_AF_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(PK_AF_bio, s_RSA_pkey);

    PK_AF_len = BIO_pending(PK_AF_bio);
    PK_AF = malloc(PK_AF_len + 1);
    if (BIO_read(PK_AF_bio, PK_AF, PK_AF_len) <= 0)
    {
        handleErrors();
    }
    PK_AF[PK_AF_len] = '\0';
#ifdef DebugAkmaInfo
    printf("\nAF pub_len = %d \n", PK_AF_len);
    printf("\n%s\n", PK_AF);
    // EVP_PKEY_CTX_free(rsa_ctx);  //it cannot free, otherwise the AF will crash
#endif
    BIO_free(PK_AF_bio);
    BN_free(exponent_bn);
}

/*
generate ECDSA key

store public key in AF_ECDSA_Pubkey;
store EVP_PKEY in s_AF_ECDSA_pkey
*/
void generateECDSA()
{
#ifdef showAKMAmethod
    printf("AF generateECDSA \n");
#endif
    // s_AF_ECDSA_pkey = EVP_PKEY_new();

    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *params = NULL;

    /* Create the context for parameter generation */
    if (NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)))
        handleErrors();

    /* Initialise the parameter generation */
    if (1 != EVP_PKEY_paramgen_init(pctx))
        handleErrors();

    /* We're going to use the ANSI X9.62 Prime 256v1 curve */
    if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1))
        handleErrors();

    /* Create the parameter object params */
    if (!EVP_PKEY_paramgen(pctx, &params))
        handleErrors();

    /* Create the context for the key generation */
    if (NULL == (kctx = EVP_PKEY_CTX_new(params, NULL)))
        handleErrors();
    /* Generate the key */
    if (1 != EVP_PKEY_keygen_init(kctx))
        handleErrors();

    if (1 != EVP_PKEY_keygen(kctx, &s_AF_ECDSA_pkey))
        handleErrors();

    // export public key to anyone
    BIO *Pubkey_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(Pubkey_bio, s_AF_ECDSA_pkey);

    AF_ECDSA_Pubkey_len = BIO_pending(Pubkey_bio);
    AF_ECDSA_Pubkey = malloc(AF_ECDSA_Pubkey_len + 1);
    if (BIO_read(Pubkey_bio, AF_ECDSA_Pubkey, AF_ECDSA_Pubkey_len) <= 0)
    {
        handleErrors();
    }
    AF_ECDSA_Pubkey[AF_ECDSA_Pubkey_len] = '\0';
#ifdef DebugAkmaInfo
    printf("\nAF ECDSA Pubkey_len = %d \n", AF_ECDSA_Pubkey_len);
    printf("\n%s\n", AF_ECDSA_Pubkey);
#endif
    BIO_free(Pubkey_bio);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(params);
}

/*
store public key in AF_ECIES_Pubkey;
*/
void generateECIES()
{

    /*use s_AF_ECDSA_pkey as ECIES key
     */

    // Serialize Home Network Public Key
    EC_KEY *eckey = NULL;
    const EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    size_t size = 1000;
    unsigned char pubkey[size];
    unsigned char privatekey[size];
    size_t a;
    BN_CTX *ctx;
    ctx = BN_CTX_new();
    eckey = EVP_PKEY_get1_EC_KEY(s_AF_ECDSA_pkey);
    const EC_POINT *ecpoint = EC_KEY_get0_public_key(eckey);
    a = EC_POINT_point2oct(ecgroup, ecpoint, EC_GROUP_get_point_conversion_form(ecgroup), pubkey, size, ctx);
    AF_ECIES_Pubkey_len = a;
    AF_ECIES_Pubkey = malloc(AF_ECIES_Pubkey_len + 1);
    memset(AF_ECIES_Pubkey, 0x00, sizeof(AF_ECIES_Pubkey));
    memcpy(AF_ECIES_Pubkey, pubkey, AF_ECIES_Pubkey_len);
    printf("AF_ECIES_Pubkey[%lu]: \n", AF_ECIES_Pubkey_len);
    BIO_dump_fp(stdout, (const char *)AF_ECIES_Pubkey, AF_ECIES_Pubkey_len);

    // EC_POINT_free(ecpoint); //can not free, otherwise s_UE_ECIES_pkey could not free.
    BN_CTX_free(ctx);
    EC_KEY_free(eckey);
    EC_GROUP_free(ecgroup);
}

void getECIES_Shared_Secret_Key(EVP_PKEY *ECIES_pkey, 
	unsigned char* pubkey, size_t pubkey_len,
	unsigned char *secret_key, size_t *p_secret_key_len
    ){
#ifdef showmethod
	printm(ebene,"AF: getECIES_Shared_Secret_Key\n");
#endif

	unsigned char *secret = NULL;
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

	f = EC_POINT_oct2point(ecgroup, peerpoint, buf, pubkey_len, NULL);
	c = EC_KEY_set_public_key(peereckey, peerpoint);
    EVP_PKEY *peerkey = NULL;
	peerkey = EVP_PKEY_new();
	d = EVP_PKEY_set1_EC_KEY(peerkey,peereckey);

	/* To serialize the public key:

	Pass the EVP_PKEY to EVP_PKEY_get1_EC_KEY() to get an EC_KEY.
	Pass the EC_KEY to EC_KEY_get0_public_key() to get an EC_POINT.
	Pass the EC_POINT to EC_POINT_point2oct() to get octets, which are just unsigned char *.
	 */

	if(NULL == (ctx = EVP_PKEY_CTX_new(ECIES_pkey, NULL))) handleErrors();

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
#ifdef DebugAkmaInfo
    printf("AF get ECIES shared secret key:(%d bytes)\n", secretLength);
	BIO_dump_fp(stdout, (const char *)secret, secretLength);
#endif
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

    // *secret_len = secretLength;
	// return secret;

	kdf(secret, secretLength, p_secret_key_len, NULL, 0, secret_key);

	if(secret != NULL) 
		OPENSSL_free(secret);

#ifdef DebugAkmaInfo
    printf("AF kdf ECIES shared secret key:(%d bytes)\n", (*p_secret_key_len));
	BIO_dump_fp(stdout, (const char *)secret_key, (*p_secret_key_len));
#endif
}

/*
decrypt enc_CT_UE_AF(in len bytes) with p_key private by RSA
return the decrypted info with dec_CT_AF_len bytes.
*/
unsigned char *Decrypt_CT_UE_AF(EVP_PKEY *p_key, unsigned char *enc_CT_UE_AF, size_t len, size_t *dec_CT_AF_len)
{
#ifdef measureAKMAfct2
    uint64_t y10, z10;
    y10 = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
    EVP_PKEY_CTX *dec_ctx = EVP_PKEY_CTX_new(p_key, NULL);
    if (EVP_PKEY_decrypt_init(dec_ctx) <= 0)
    {
        handleErrors();
    }

    if (EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
        handleErrors();
    }

    unsigned char *dec_CT_UE_AF;
    if (EVP_PKEY_decrypt(dec_ctx, NULL, dec_CT_AF_len, enc_CT_UE_AF, len) <= 0)
    {
        handleErrors();
    }
#ifdef DebugAkmaInfo
    printf("Determimed plaintext to be of length: %d:\n", *dec_CT_AF_len);
#endif
    dec_CT_UE_AF = OPENSSL_malloc(*dec_CT_AF_len);
    if (!dec_CT_UE_AF)
    {
        handleErrors();
    }

    if (EVP_PKEY_decrypt(dec_ctx, dec_CT_UE_AF, dec_CT_AF_len, enc_CT_UE_AF, len) <= 0)
    {
        handleErrors();
    }
#ifdef measureAKMAfct2
    z10 = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
    printf("AF PKDec step 14 Decrypt_CT_UE_AF Duration %lu ns\n", z10 - y10);
#endif
#ifdef DebugAkmaInfo
    printf("Decrypted CT_UE_AF is:\n");
    BIO_dump_fp(stdout, (const char *)dec_CT_UE_AF, *dec_CT_AF_len);
#endif
    // EVP_PKEY_CTX_free(ctx);

    return dec_CT_UE_AF;
}

/*
Sign ResAF with s_RSA_pkey
ResAF = V + a1
unsigned char *V: input
size_t V_len: input
unsigned char *a1 : input
int a_len : input


unsigned char *Res_AF: output
unsigned int *pRes_AF_len: output
unsigned char *Res_AF_Sign: output
unsigned int *pRes_AF_Sign_len: output
*/
void ResAF_Sign(unsigned char *V, size_t V_len,
                unsigned char *a1, int a_len,
                unsigned char *Res_AF, unsigned int *pRes_AF_len,
                unsigned char *Res_AF_Sign, unsigned int *pRes_AF_Sign_len)
{

#ifdef measureAKMAfct2
    uint64_t y10, z10;
    y10 = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

    // (*pRes_AF_len) = V_len + a_len + b_len;
    (*pRes_AF_len) = V_len + a_len;

    memcpy(Res_AF, V, V_len);
    memcpy(Res_AF + V_len, a1, a_len);
    // memcpy(Res_AF + V_len + a_len, b, b_len);

    // start to sign
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(mdctx);
    if (!EVP_SignInit_ex(mdctx, EVP_sha256(), NULL))
    {
        printf("EVP_SignInit_ex err\n");
        handleErrors();
        return;
    }

    if (!EVP_SignUpdate(mdctx, Res_AF, (*pRes_AF_len)))
    {
        handleErrors();
        return;
    }

    // if(!EVP_SignFinal(mdctx,Res_AF_Sign,pRes_AF_Sign_len,s_RSA_pkey))
    // use ecdsa key
    if (!EVP_SignFinal(mdctx, Res_AF_Sign, pRes_AF_Sign_len, s_AF_ECDSA_pkey))
    {
        printf("EVP_SignFinal err\n");
        handleErrors();
        return;
    }
#ifdef measureAKMAfct2
    z10 = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
    printf("AF step 14 ResAF_Sign Duration %lu ns\n", z10 - y10);
#endif
#ifdef DebugAkmaInfo
    printf("AF Sig Res_AF sign value is[%d]:\n", (*pRes_AF_Sign_len));
    BIO_dump_fp(stdout, (const char *)Res_AF_Sign, (*pRes_AF_Sign_len));
#endif
    EVP_MD_CTX_free(mdctx);
}

int main(void)
{
    printm(ebene, "Start AF\n");

    // generate rsa key
    //  Generate key pair

    // generateRSAKey2();
    generateECDSA();
    generateECIES();

    EVP_PKEY *p_v = NULL;
    unsigned char V[65];
    size_t V_len;

    p_v = EVP_PKEY_new();
    getECKey(p_v, V, &V_len);

    //     unsigned char b[16];
    // 	memset(b, 0xFF, sizeof(b));
    // 	RAND_bytes(b, 16);
    // #ifdef DebugAkmaInfo
    // 	printf("AF print rand b: ");
    // 	for (int i = 0; i < sizeof(b); i++)
    // 	{
    // 		printf("%02x", b[i]);
    // 	}
    // 	printf("\n");
    // #endif

    // Variable declaration
    struct sockaddr_in svAddr;
    struct sockaddr_in recvAddr;
    socklen_t addrlen = sizeof(recvAddr);
    int sv;
    int recvlen;
    int sendlen;
    unsigned char buf[BUFSIZE];
    unsigned char send_buf[BUFSIZE];
    // se_av_t se_av;

    // Set up server
    if ((sv = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("cannot create socket");
        exit(1);
    }

    memset((char *)&svAddr, 0, sizeof(svAddr));
    svAddr.sin_family = AF_INET;
    svAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    svAddr.sin_port = htons(AF_SV_PORT);

    if (bind(sv, (struct sockaddr *)&svAddr, sizeof(svAddr)) < 0)
    {
        perror("Bind failed");
        return 0;
    }

    printf("AF-server started, listening on port %d\n", AF_SV_PORT);
    size_t pubKey_len = 0;
    unsigned char pubKey[65];

    // loop for receiving
    for (int idx = 0; idx < 2; idx++)
    {
        printf("waiting on port %d\n", AF_SV_PORT);
        memset(buf, 0x00, sizeof(buf));
        recvlen = recvfrom(sv, buf, BUFSIZE, 0, (struct sockaddr *)&recvAddr, &addrlen);
        if (recvlen > 0)
        {
            buf[recvlen] = 0;
#ifdef CommCosts
            printf("AF receive message from UE(%d bytes)\n", recvlen);
#ifdef DebugAkmaInfo
            for (int i = 0; i < recvlen; i++)
            {
                printf("%02x", buf[i]);
            }
            printf("\n");
#endif
#endif
            // init UE(USIM)--> AF
            if (strncmp(buf, "getAFPUBKEY", 11) == 0)
            {
                /*"getAFPUBKEY" + UE_ECIES_Pubkey_len(4 Bytes) + UE_ECIES_Pubkey
                 */
                int offset = strlen("getAFPUBKEY");
                unsigned char str_UE_ECIES_Pubkey_len[5];
                memset(str_UE_ECIES_Pubkey_len, 0x00, sizeof(str_UE_ECIES_Pubkey_len));
                memcpy(str_UE_ECIES_Pubkey_len, buf + offset, 4);
                offset += 4;
                UE_ECIES_Pubkey_len = atoi(str_UE_ECIES_Pubkey_len);
                UE_ECIES_Pubkey = malloc(UE_ECIES_Pubkey_len + 1);
                memset(UE_ECIES_Pubkey, 0x00, sizeof(UE_ECIES_Pubkey));
                memcpy(UE_ECIES_Pubkey, buf + offset, UE_ECIES_Pubkey_len);
                offset += UE_ECIES_Pubkey_len;
#ifdef DebugAkmaInfo
		printf("AF get UE_ECIES_Pubkey:(%d bytes)\n", UE_ECIES_Pubkey_len);
		BIO_dump_fp(stdout, (const char *)UE_ECIES_Pubkey, UE_ECIES_Pubkey_len);
#endif
                /*get ECIES Shared Secret key,  use to decrypt CT_UE_AF in step 14*/
                getECIES_Shared_Secret_Key(
                    s_AF_ECDSA_pkey, UE_ECIES_Pubkey, UE_ECIES_Pubkey_len,
                    AF_UE_ECIES_Shared_Secret_Key, &AF_UE_ECIES_Shared_Secret_Key_len
                );

                /* send response to UE("GetPublicKeyResponse" +
                    AF_ECDSA_Pubkey_len(4 Bytes) + AF_ECDSA_Pubkey +
                    AF_ECIES_Pubkey_len(4 Bytes) + AF_ECIES_Pubkey)
                */
                memset(send_buf, 0x00, sizeof(send_buf));
                // Application Session Establishment Response
                char *AFResponse = "PublicKeyRes";
                int reslen = strlen(AFResponse);
                offset = 0;
                memcpy(send_buf + offset, AFResponse, reslen);
                offset += reslen;
                sprintf(send_buf + offset, "%04d", AF_ECDSA_Pubkey_len);
                offset += 4;
                memcpy(send_buf + offset, AF_ECDSA_Pubkey, AF_ECDSA_Pubkey_len);
                offset += AF_ECDSA_Pubkey_len;
                sprintf(send_buf + offset, "%04d", AF_ECIES_Pubkey_len);
                offset += 4;
                memcpy(send_buf + offset, AF_ECIES_Pubkey, AF_ECIES_Pubkey_len);
                offset += AF_ECIES_Pubkey_len;

                if (sendto(sv, send_buf, offset, 0, (struct sockaddr *)&recvAddr, addrlen) < 0)
                    perror("Send PublicKeyResponse");
#ifdef CommCosts
                printf("AF send message to UE(%d bytes)\n", offset);
#ifdef DebugAkmaInfo
                for (int i = 0; i < offset; i++)
                {
                    printf("%02x", send_buf[i]);
                }
                printf("\n");
#endif
#endif
            }
            else if (strncmp(buf, "ASERequest", strlen("ASERequest")) == 0)
            /*step 6 (UE-->AF)*/
            {
                Application_Session_Establishment_Request_AF(&g_a_kid);
#ifdef CommCosts
                printf("AKMA step 6 (UE-->AF) AF received message from UE(%d bytes)\n", recvlen);
#ifdef DebugAkmaInfo
                for (int i = 0; i < recvlen; i++)
                {
                    printf("%02x", buf[i]);
                }
                printf("\n");

#endif
#endif

#ifdef measureAKMAfct
                uint64_t y, z;
                y = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

                /*
               buf = "ASERequest" + g_a_kid +
            Enc_CT_UE_AF_len(4 bytes) + Enc_CT_UE_AF +
            SEnc_CT_UE_AAnF_len(4 bytes) + SEnc_CT_UE_AAnF + CT_UE_AAnF_TAG(2 bytes)
                */
                int akid_buf_len = sizeof(a_kid_t);
                unsigned char akid_buf[akid_buf_len];

                int offset = 10;
                memcpy(akid_buf, buf + offset, akid_buf_len);
                offset += akid_buf_len;

                // Parse2AKID(buf + 10, recvlen - 10, &g_a_kid);
                Parse2AKID(akid_buf, akid_buf_len, &g_a_kid);
#ifdef measureAKMAfct
                z = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
                // printf("A: %lu \n",y);
                // printf("B: %lu \n",z);
                printf("AF step 6 Duration %lu ns\n", z - y);
#endif

#ifdef measureAKMAfct
                uint64_t y2, z2;
                y2 = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
                unsigned char enc_CT_UE_AAnF[BUFSIZ];
                unsigned char CT_UE_AAnF_TAG[TAG_SIZE];
                unsigned char enc_CT_UE_AF[BUFSIZ];
                unsigned char str_enc_CT_UE_AF_len[5];
                unsigned char str_enc_CT_UE_AAnF_len[5];

                memset(str_enc_CT_UE_AF_len, 0x00, sizeof(str_enc_CT_UE_AF_len));
                memcpy(str_enc_CT_UE_AF_len, buf + offset, 4);
                offset += 4;
                size_t enc_CT_UE_AF_len = atoi(str_enc_CT_UE_AF_len);
                memcpy(enc_CT_UE_AF, buf + offset, enc_CT_UE_AF_len);
                offset += enc_CT_UE_AF_len;

                memset(str_enc_CT_UE_AAnF_len, 0x00, sizeof(str_enc_CT_UE_AAnF_len));
                memcpy(str_enc_CT_UE_AAnF_len, buf + offset, 4);
                offset += 4;
                size_t enc_CT_UE_AAnF_len = atoi(str_enc_CT_UE_AAnF_len);
                memcpy(enc_CT_UE_AAnF, buf + offset, enc_CT_UE_AAnF_len);
                offset += enc_CT_UE_AAnF_len;
                memcpy(CT_UE_AAnF_TAG, buf + offset, TAG_SIZE);
                offset += TAG_SIZE;

                // set g_a_kid;
                memset(g_af_id.fqdn, 0xFF, sizeof(g_af_id.fqdn));
                memset(g_af_id.uaid, 0xFF, sizeof(g_af_id.uaid));
#ifdef measureAKMAfct
                z2 = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
                printf("AF step 6 akma+ add Duration %lu ns\n", z2 - y2);
#endif
                unsigned char SEnc_CT_AAnF_UE[BUFSIZ];
                unsigned int SEnc_CT_AAnF_UE_Len;
                unsigned char CT_AAnF_UE_TAG[TAG_SIZE];

                // step 7 to step 13
                Naanf_AKMA_ApplicationKey_GetRequest_AF(&g_a_kid, &g_af_id,
                                                        enc_CT_UE_AAnF, enc_CT_UE_AAnF_len, CT_UE_AAnF_TAG,
                                                        SEnc_CT_AAnF_UE, &SEnc_CT_AAnF_UE_Len, CT_AAnF_UE_TAG);

#ifdef measureAKMAfct
                uint64_t y3, z3;
                y3 = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
                char *ASEResponse = "ASEResponse";
                memset(send_buf, 0x00, sizeof(send_buf));
                sendlen = 0;

                memcpy(send_buf + sendlen, ASEResponse, strlen(ASEResponse));
                sendlen += strlen(ASEResponse);
#ifdef measureAKMAfct
                z3 = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
                // printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
                //  printf("A: %lu \n",y1);
                //  printf("B: %lu \n",z1);
                printf("AF step 14 Duration %lu ns\n", z3 - y3);
#endif

#ifdef measureAKMAfct
                uint64_t y1, z1;
                y1 = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
                // unsigned char *CT_UE_AF;
                size_t CT_UE_AF_len = 0;
                // CT_UE_AF = Decrypt_CT_UE_AF(s_RSA_pkey, enc_CT_UE_AF, enc_CT_UE_AF_len, &CT_UE_AF_len);
                unsigned char CT_UE_AF[BUFSIZ];
                memset(CT_UE_AF, 0x00, sizeof(CT_UE_AF));
                CT_UE_AF_len = decrypt(enc_CT_UE_AF, enc_CT_UE_AF_len, 
                    AF_UE_ECIES_Shared_Secret_Key, 0, CT_UE_AF);
                
                unsigned char a1[16];
                unsigned char U[65];
                memcpy(U, CT_UE_AF, sizeof(U));
                memcpy(a1, CT_UE_AF + sizeof(U), sizeof(a1));

                unsigned char Res_AF[128];
                unsigned int Res_AF_len = 0;

                unsigned char Res_AF_Sign[1024];
                unsigned int Res_AF_Sign_len = 0;

                // ResAF_Sign(V, V_len, a1 ,16, b, 16,
                //     Res_AF, &Res_AF_len, Res_AF_Sign, &Res_AF_Sign_len);

                ResAF_Sign(V, V_len, a1, sizeof(a1),
                           Res_AF, &Res_AF_len, Res_AF_Sign, &Res_AF_Sign_len);
#ifdef measureAKMAfct
                z1 = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
                printf("AF step 14 akma+ add Sign Duration %lu ns\n", z1 - y1);
#endif

#ifdef DebugAkmaInfo
                printf("AF print enc_CT_UE_AAnF: (len:%d) is:\n", enc_CT_UE_AAnF_len);
                BIO_dump_fp(stdout, (const char *)enc_CT_UE_AAnF, enc_CT_UE_AAnF_len);
                printf("AF print enc_CT_UE_AF: (len:%d) is:\n", enc_CT_UE_AF_len);
                BIO_dump_fp(stdout, (const char *)enc_CT_UE_AF, enc_CT_UE_AF_len);
                printf("AF print dec_CT_UE_AF: (len:%d) is:\n", CT_UE_AF_len);
                BIO_dump_fp(stdout, (const char *)CT_UE_AF, CT_UE_AF_len);
                printf("AF print a1: (len:%d) is:\n", sizeof(a1));
                BIO_dump_fp(stdout, (const char *)a1, sizeof(a1));
#endif

                // Application Session Establishment Response

                // "ASEResponse" + SEnc_CT_AAnF_UE_Len(4 bytes) + SEnc_CT_AAnF_UE + CT_AAnF_UE_TAG(2 bytes)
                //                 Res_AF_len(4 bytes) + Res_AF + Res_AF_Sign_len(4 bytes) + Res_AF_Sign

#ifdef measureAKMAfct
                uint64_t y4, z4;
                y4 = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
                // char str_Res_AAnF_len[5];
                // sprintf(str_Res_AAnF_len, "%04d", g_Res_AAnF_len);

                // memcpy(send_buf + sendlen , str_Res_AAnF_len, 4);
                // sendlen += 4;

                // memcpy(send_buf + sendlen , g_Res_AAnF, g_Res_AAnF_len);

                // sendlen += g_Res_AAnF_len;

                // memcpy(send_buf + sendlen , g_Res_AAnF_Sign, 128);
                // sendlen += 128;

                sprintf(send_buf + sendlen, "%04d", SEnc_CT_AAnF_UE_Len);
                sendlen += 4;
                memcpy(send_buf + sendlen, SEnc_CT_AAnF_UE, SEnc_CT_AAnF_UE_Len);
                sendlen += SEnc_CT_AAnF_UE_Len;
                memcpy(send_buf + sendlen, CT_AAnF_UE_TAG, TAG_SIZE);
                sendlen += TAG_SIZE;

                char str_Res_AF_len[5];
                sprintf(str_Res_AF_len, "%04d", Res_AF_len);

                memcpy(send_buf + sendlen, str_Res_AF_len, 4);
                sendlen += 4;

                memcpy(send_buf + sendlen, Res_AF, Res_AF_len);
                sendlen += Res_AF_len;

                sprintf(send_buf + sendlen, "%04d", Res_AF_Sign_len);
                sendlen += 4;
                memcpy(send_buf + sendlen, Res_AF_Sign, 128);
                sendlen += 128;

#ifdef DebugAkmaInfo
                printf("g_k_af.k_af (len:%d) is:\n", sizeof(g_k_af.k_af));
                BIO_dump_fp(stdout, (const char *)g_k_af.k_af, sizeof(g_k_af.k_af));
#endif
                unsigned char *Ks_v = NULL;
                size_t Ks_v_Len = 0;

                Ks_v = getSharedKey(p_v, U, &Ks_v_Len);

#ifdef DebugAkmaInfo
                printf("AF print Ksv(%d): \n", Ks_v_Len);
                BIO_dump_fp(stdout, (const char *)Ks_v, Ks_v_Len);
                // for (int i = 0; i < Ks_v_Len; i++)
                // {
                //     printf("%02x", Ks_v[i]);
                // }
                // printf("\n");
#endif
                unsigned char K_AF_prime[128];
                size_t K_AF_prime_Len = 128;
                unsigned char K_AF_Ks_v[BUFSIZ];
                offset = 0;
                memcpy(K_AF_Ks_v + offset, g_k_af.k_af, sizeof(g_k_af.k_af));
                offset += sizeof(g_k_af.k_af);

                memcpy(K_AF_Ks_v + offset, Ks_v, Ks_v_Len);
                offset += Ks_v_Len;

                kdf(K_AF_Ks_v, offset, &K_AF_prime_Len, NULL, 0, K_AF_prime);
#ifdef DebugAkmaInfo
                printf("K_AF_prime (len:%d) is:\n", K_AF_prime_Len);
                BIO_dump_fp(stdout, (const char *)K_AF_prime, K_AF_prime_Len);
#endif

#ifdef measureAKMAfct
                z4 = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
                printf("AF step 14 akma+ add Duration %lu ns\n", z4 - y4);
#endif

#ifdef CommCosts
                printf("AKMA step 14 (AF-->UE) AF send message to UE(%d bytes)\n", sendlen);
#ifdef DebugAkmaInfo
                for (int i = 0; i < sendlen; i++)
                {
                    printf("%02x", send_buf[i]);
                }
                printf("\n");
#endif
#endif
                if (sendto(sv, send_buf, sendlen, 0, (struct sockaddr *)&recvAddr, addrlen) < 0)
                    perror("Send ASEResponse");
                Application_Session_Establishment_Response_AF();
            }
        }
        else
        {
            perror("recvfrom error");
            printf("Message Unknown, recvlen = %d\n", recvlen);
        }
    }
    close(sv);
    if (PK_AF != NULL)
        free(PK_AF);
    if (AF_ECDSA_Pubkey != NULL)
        free(AF_ECDSA_Pubkey);
    if (AF_ECIES_Pubkey != NULL)
        free(AF_ECIES_Pubkey);
    if (s_AF_ECDSA_pkey != NULL)
        EVP_PKEY_free(s_AF_ECDSA_pkey);
    printm(ebene, "Authentication End\n");
    return EXIT_SUCCESS;
}