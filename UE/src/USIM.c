/*
 * USIM.c
 *
 */

#include "USIM.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include "ffunction.h"
#include "defs.h"

#define CL_PORT 51111
#define CL_AF_PORT 51112
#define SV_PORT 50001
#define BUFSIZE 2048
#define AF_PORT 50002




static size_t sizeHNPK = 65;
static unsigned char homeNetworkPublicKey[65];
// unsigned char s_RSA_PK_AAnF[BUFSIZE];
static size_t s_RSA_pubkey_len;
const int hashmaxlen = 256;
static supi_t supi;
static uint8_t key_k[SIZE_K];
static uint8_t sqn_ue[6];
static EVP_PKEY *s_AF_pkey;


extern unsigned char PK_AF[65];
extern size_t PK_AF_len;

// ECDSA key
extern char *AF_ECDSA_Pubkey; // Public key
extern size_t AF_ECDSA_Pubkey_len;                // Length of public key

// ECIES key
extern char *AF_ECIES_Pubkey; // Public key
extern size_t AF_ECIES_Pubkey_len;                // Length of public key

extern EVP_PKEY *s_AF_ECDSA_pkey;

extern EVP_PKEY *s_UE_ECIES_pkey;
extern char *UE_ECIES_Pubkey; 
extern size_t UE_ECIES_Pubkey_len;  
extern char UE_AF_ECIES_Shared_Secret_Key[128]; 
extern size_t UE_AF_ECIES_Shared_Secret_Key_len;   

// extern unsigned char PK_AAnF[1024];
// extern size_t PK_AAnF_len;

extern EVP_PKEY *p_u;
extern unsigned char U[65];
extern size_t U_len;

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

void initUSIM(supi_t *l_supi)
{
#ifdef showmethod
	printf("USIM: initUSIM\n");
#endif
	for (int idx = 0; idx < 3; idx++)
	{
		supi.mcc_mnc[idx] = 0;
		l_supi->mcc_mnc[idx] = supi.mcc_mnc[idx];
	}
	for (int idx = 0; idx < 5; idx++)
	{
		supi.msin[idx] = 0;
		l_supi->msin[idx] = supi.msin[idx];
	}
	for (int idx = 0; idx < SIZE_K; idx++)
	{
		key_k[idx] = 0;
	}
	for (int idx = 0; idx < 6; idx++)
	{
		sqn_ue[idx] = 0;
	}
	get_HomeNetworkPublicKey("127.0.0.1");

	printf("USIM:  print HomeNetworkPublicKey:");
	for (int idx = 0; idx < sizeof(homeNetworkPublicKey); idx++)
	{
		printf("%02x", homeNetworkPublicKey[idx]);
	}
	printf("\n");
	GetPK_AF("127.0.0.1");
}

int get_HomeNetworkPublicKey(char *servAddr)
{
#ifdef showmethod
	printf("USIM: get_HomeNetworkPublicKey\n");
#endif
	// create client socket
	struct sockaddr_in clAddr;
	struct sockaddr_in seafAddr;
	socklen_t addrlen = sizeof(seafAddr);
	int cl, recvlen;
	int slen = sizeof(seafAddr);
	unsigned char buf[BUFSIZE];
	char *server = "127.0.0.1";

	if ((cl = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		perror("cannot create socket");
		exit(1);
	}

	memset((char *)&clAddr, 0, sizeof(clAddr));
	clAddr.sin_family = AF_INET;
	clAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	clAddr.sin_port = htons(CL_PORT);
	if (bind(cl, (struct sockaddr *)&clAddr, sizeof(clAddr)) < 0)
	{
		perror("Bind failed");
		close(cl);
		return 0;
	}

	memset((char *)&seafAddr, 0, sizeof(seafAddr));
	seafAddr.sin_family = AF_INET;
	seafAddr.sin_port = htons(SV_PORT);
	if (inet_aton(servAddr, &seafAddr.sin_addr) == 0)
	{
		fprintf(stderr, "inet_aton() failed\n");
		exit(1);
	}

	sprintf(buf, "getHNPK");
	if (sendto(cl, buf, strlen(buf), 0, (struct sockaddr *)&seafAddr, slen) == -1)
	{
		perror("sendto");
		exit(1);
	}

	// get public key
	// buf = homeNetworkPublicKey
	recvlen = recvfrom(cl, buf, BUFSIZE, 0, (struct sockaddr *)&seafAddr, &slen);
	if (recvlen >= 0)
	{
		// buf[65] = 0;
		memcpy(homeNetworkPublicKey, buf, 65);
		// PK_AAnF_len = recvlen - 65;
		// PK_AAnF[PK_AAnF_len] = 0;
		// memcpy(PK_AAnF, buf + 65, PK_AAnF_len );
#ifdef DebugAkmaInfo
		// printf("usim receive message from seaf(%d bytes), s_RSA_pubkey_len = %d\n", recvlen, PK_AAnF_len);
		// printf("usim print s_RSA_PK_AAnF[%d]: \n%s \n", PK_AAnF_len, PK_AAnF);
		// BIO_dump_fp(stdout, (const char *)PK_AAnF, PK_AAnF_len);
#endif
		// printf("Msg[%d]: \t%s \n", recvlen, buf);
	}
	// close client-socket
	close(cl);

	return 1;
}

void generateECIES(){
	
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY  *params = NULL;
    

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
        handleErrors();\
    if (1 != EVP_PKEY_keygen(kctx, &s_UE_ECIES_pkey))
        handleErrors();\
	// Serialize Home Network Public Key
	EC_KEY* eckey = NULL;
	const EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	size_t size = 1000;
	unsigned char pubkey[size];
	unsigned char privatekey[size];
	size_t a;
	BN_CTX* ctx;
	ctx = BN_CTX_new();
	//EVP_PKEY_get1_EC_KEY() return the referenced key in pkey or NULL if the key is not of the correct type. 
	//so it can not free befroe s_UE_ECIES_pkey
	eckey = EVP_PKEY_get1_EC_KEY(s_UE_ECIES_pkey);
	const EC_POINT* ecpoint = EC_KEY_get0_public_key(eckey);
	a = EC_POINT_point2oct(ecgroup ,ecpoint ,EC_GROUP_get_point_conversion_form(ecgroup),pubkey,size,ctx);
    UE_ECIES_Pubkey_len = a;
    UE_ECIES_Pubkey = malloc(UE_ECIES_Pubkey_len + 1);
    memset(UE_ECIES_Pubkey, 0x00, sizeof(UE_ECIES_Pubkey));
	memcpy(UE_ECIES_Pubkey, pubkey,UE_ECIES_Pubkey_len);
	printf("UE_ECIES_Pubkey[%lu]: \n",UE_ECIES_Pubkey_len);
	BIO_dump_fp(stdout,  (const char *)UE_ECIES_Pubkey, UE_ECIES_Pubkey_len);

    BN_CTX_free(ctx);
    EC_KEY_free(eckey);
    EC_GROUP_free(ecgroup);

    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(params);

}

void getECIES_Shared_Secret_Key(EVP_PKEY *ECIES_pkey, 
	unsigned char* pubkey, size_t pubkey_len,
	unsigned char *secret_key, size_t *p_secret_key_len
    ){
#ifdef showmethod
	printf("func usim: getECIES_Shared_Secret_Key\n");
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
    printf("USIM get ECIES shared secret key:(%d bytes)\n", secretLength);
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

	// *secret_len = secretLength;
	// return secret;

	kdf(secret, secretLength, p_secret_key_len, NULL, 0, secret_key);

	if(secret != NULL) 
		OPENSSL_free(secret);

#ifdef DebugAkmaInfo
    printf("USIM kdf ECIES shared secret key:(%d bytes)\n", (*p_secret_key_len));
	BIO_dump_fp(stdout, (const char *)secret_key, (*p_secret_key_len));
#endif

	
}

/*
get AF_ECDSA_Pubkey, AF_ECIES_Pubkey
*/
int GetPK_AF(char *servAddr)
{
#ifdef showmethod
	printf("USIM: GetPK_AF\n");
#endif
	// generate ECIES key
	generateECIES();
	
	// send request to AF
	//  create client socket
	struct sockaddr_in clAddr;
	struct sockaddr_in afAddr;
	socklen_t addrlen = sizeof(afAddr);
	int cl, recvlen;
	int slen = sizeof(afAddr);
	unsigned char buf[BUFSIZE];
	unsigned char recv_buf[BUFSIZE];
	char *server = "127.0.0.1";

	if ((cl = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		perror("cannot create socket");
		exit(1);
	}

	memset((char *)&clAddr, 0, sizeof(clAddr));
	clAddr.sin_family = AF_INET;
	clAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	clAddr.sin_port = htons(CL_AF_PORT);
	if (bind(cl, (struct sockaddr *)&clAddr, sizeof(clAddr)) < 0)
	{
		perror("Bind failed");
		close(cl);
		return 0;
	}

	memset((char *)&afAddr, 0, sizeof(afAddr));
	afAddr.sin_family = AF_INET;
	afAddr.sin_port = htons(AF_PORT);
	if (inet_aton(servAddr, &afAddr.sin_addr) == 0)
	{
		fprintf(stderr, "inet_aton() failed\n");
		exit(1);
	}
	/*
	"getAFPUBKEY" + UE_ECIES_Pubkey_len(4 Bytes) + UE_ECIES_Pubkey
	*/
	memset(buf, 0x00, sizeof(buf));
	sprintf(buf, "getAFPUBKEY");
	int offset = 0;
	offset += strlen("getAFPUBKEY");

	sprintf(buf + offset, "%04d", UE_ECIES_Pubkey_len);
	offset += 4;

	memcpy(buf + offset, UE_ECIES_Pubkey, UE_ECIES_Pubkey_len);
	offset += UE_ECIES_Pubkey_len;

	if (sendto(cl, buf, offset, 0, (struct sockaddr *)&afAddr, slen) == -1)
	{
		perror("sendto");
		exit(1);
	}

	// get public key
	recvlen = recvfrom(cl, recv_buf, BUFSIZE, 0, (struct sockaddr *)&afAddr, &slen);

	if (recvlen >= 0)
	{
		printf("recv from AF(%d bytes): ", recvlen);
		for (int i = 0; i < recvlen; i++)
		{
			printf("%02x", recv_buf[i]);
		}
		printf("\n");
	}
	if (strncmp(recv_buf, "PublicKeyRes", 12) == 0)
	{
		/* "GetPublicKeyResponse" + 
                    AF_ECDSA_Pubkey_len(4 Bytes) + AF_ECDSA_Pubkey +
                    AF_ECIES_Pubkey_len(4 Bytes) + AF_ECIES_Pubkey)
		*/
		int offset = 12;
		unsigned char str_AF_ECDSA_Pubkey_len[5];
		memset(str_AF_ECDSA_Pubkey_len, 0x00, sizeof(str_AF_ECDSA_Pubkey_len));
		memcpy(str_AF_ECDSA_Pubkey_len, recv_buf + offset, 4);
		offset += 4;
		AF_ECDSA_Pubkey_len = atoi(str_AF_ECDSA_Pubkey_len);
		AF_ECDSA_Pubkey = malloc(AF_ECDSA_Pubkey_len + 1);
		memset(AF_ECDSA_Pubkey, 0x00, sizeof(AF_ECDSA_Pubkey));
		memcpy(AF_ECDSA_Pubkey, recv_buf + offset, AF_ECDSA_Pubkey_len);
		offset += AF_ECDSA_Pubkey_len;

		unsigned char str_AF_ECIES_Pubkey_len[5];
		memset(str_AF_ECIES_Pubkey_len, 0x00, sizeof(str_AF_ECIES_Pubkey_len));
		memcpy(str_AF_ECIES_Pubkey_len, recv_buf + offset, 4);
		offset += 4;
		AF_ECIES_Pubkey_len = atoi(str_AF_ECIES_Pubkey_len);
		AF_ECIES_Pubkey = malloc(AF_ECIES_Pubkey_len + 1);
		memset(AF_ECIES_Pubkey, 0x00, sizeof(AF_ECIES_Pubkey));
		memcpy(AF_ECIES_Pubkey, recv_buf + offset, AF_ECIES_Pubkey_len);
		offset += AF_ECIES_Pubkey_len;


#ifdef DebugAkmaInfo
		printf("UE get AF_ECDSA_Pubkey:(%d bytes)\n", AF_ECIES_Pubkey_len);
		BIO_dump_fp(stdout, (const char *)AF_ECDSA_Pubkey, AF_ECDSA_Pubkey_len);
		printf("UE get AF_ECIES_Pubkey:(%d bytes)\n", AF_ECIES_Pubkey_len);
		BIO_dump_fp(stdout, (const char *)AF_ECIES_Pubkey, AF_ECIES_Pubkey_len);
#endif
		// load s_AF_ECDSA_pkey
		BIO *UE_bio = NULL;
		if (NULL == (UE_bio = BIO_new(BIO_s_mem())))
			handleErrors();

		if (BIO_puts(UE_bio, AF_ECDSA_Pubkey) < 1)
			handleErrors();

		if (NULL == (s_AF_ECDSA_pkey = PEM_read_bio_PUBKEY(UE_bio, NULL, NULL, NULL)))
		{
			handleErrors();
		}
		BIO_free(UE_bio);

		// get UE_AF_ECIES_Shared_Secret_Key
		getECIES_Shared_Secret_Key(
                    s_UE_ECIES_pkey, AF_ECIES_Pubkey, AF_ECIES_Pubkey_len,
					UE_AF_ECIES_Shared_Secret_Key, &UE_AF_ECIES_Shared_Secret_Key_len);
		printf("s_UE_ECIES_pkey 4 %p\n", s_UE_ECIES_pkey);
	}
	// close client-socket
	close(cl);
	return 1;
}


/*EVP_PKEY* get_peerkey(EVP_PKEY* keys) // it contains public + private
{
	int len = 0;
	unsigned char *buf = NULL, *p;
	const unsigned char *p2;
	EVP_PKEY* pkey;

	len = i2d_PUBKEY(keys, NULL); // find out required buffer length
	buf = (unsigned char*) OPENSSL_malloc(len); //allocate
	p = buf;
	len = i2d_PUBKEY(keys, &p);

	p2 = buf;
	pkey = d2i_PUBKEY(NULL, &p2, len);
	if (pkey == NULL) {
		fprintf(stderr, "d2i_PUBKEY failed\n");
	}
	OPENSSL_free(buf);

	return pkey;
}
*/
unsigned char *getSharedSecret(size_t *secret_len, suci_t *suci_ecc)
{
#ifdef showmethod
	printf("USIM: getSharedSecret\n");
#endif
#ifdef measurefct
	uint64_t y, z;
	y = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	EVP_PKEY_CTX *pctx, *kctx;
	EVP_PKEY_CTX *ctx;
	unsigned char *secret;
	EVP_PKEY *pkey = NULL, *peerkey = NULL, *params = NULL;
	size_t secretLength;
	/* NB: assumes pkey, peerkey have been already set up */

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
	if (1 != EVP_PKEY_keygen(kctx, &pkey))
		handleErrors();

	// Put public key in suci-struct
	EC_KEY *eckey = NULL;
	// EC_POINT* ecpoint = NULL;
	const EC_GROUP *ecgroup_pk = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	size_t size = 1000;
	unsigned char suci_pubkey[size];

	size_t a;
	BN_CTX *pkctx;

	pkctx = BN_CTX_new();

	// ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	eckey = EVP_PKEY_get1_EC_KEY(pkey);

	const EC_POINT *ecpoint = EC_KEY_get0_public_key(eckey);
	a = EC_POINT_point2oct(ecgroup_pk, ecpoint, EC_GROUP_get_point_conversion_form(ecgroup_pk), suci_pubkey, size, pkctx);
#ifdef testb
	printf("Publickey[%lu]: ", a);
	for (int idx = 0; idx < a; idx++)
	{
		printf("%x", suci_pubkey[idx]);
	}
	printf("\n");
#endif
	memcpy(suci_ecc->ecc_pub_key, suci_pubkey, a);

	/* Get the peer's public key, and provide the peer with our public key -
	 * how this is done will be specific to your circumstances */
	// peerkey = get_peerkey(pkey);
	EC_POINT *peerpoint;
	EC_KEY *peereckey;

	const EC_GROUP *ecgroup; // = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

	peereckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	ecgroup = EC_KEY_get0_group(peereckey);
	peerpoint = EC_POINT_new(ecgroup);
	const unsigned char *buf = homeNetworkPublicKey;
	int b = -5, c = -5, d = -5;
#ifdef testb
	printf("HomeNetworkPublicKey[%lu]: ", sizeHNPK);
	for (int idx = 0; idx < sizeHNPK; idx++)
	{
		printf("%x", homeNetworkPublicKey[idx]);
	}
	printf("\n");
#endif
	b = EC_POINT_oct2point(ecgroup, peerpoint, buf, 65, NULL);
	c = EC_KEY_set_public_key(peereckey, peerpoint);
	peerkey = EVP_PKEY_new();
	d = EVP_PKEY_set1_EC_KEY(peerkey, peereckey);

	// peerkey = get_peerkey(peerkey);

	/* Create the context for the shared secret derivation */
	if (NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL)))
		handleErrors();
	/* Initialise */
	if (1 != EVP_PKEY_derive_init(ctx))
		handleErrors();
	/* Provide the peer public key */
	if (1 != EVP_PKEY_derive_set_peer(ctx, peerkey))
		handleErrors();
	/* Determine buffer length for shared secret */
	if (1 != EVP_PKEY_derive(ctx, NULL, &secretLength))
		handleErrors();
	/* Create the buffer */
	if (NULL == (secret = OPENSSL_malloc(secretLength)))
		handleErrors();
	/*for(int i=0; i<secret_len;i++){
		printf("%x", secret[i]);
	}*/
	/* Derive the shared secret */

	int e = EVP_PKEY_derive(ctx, secret, &secretLength);
	// if(1 != (e)) handleErrors();

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(peerkey);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(kctx);
	EVP_PKEY_free(params);
	EVP_PKEY_CTX_free(pctx);
	*secret_len = secretLength;

	// TODO: sharedsecret doesn't work -> fixed secret
	/*for(int cnt=0; cnt<secretLength;cnt++){
		secret[cnt] = '0';
	}*/

#ifdef measurefct
	z = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n", y);
	printf("B: %lu \n", z);
	printf("getSharedSecret Duration %lu ns\n", z - y);
#endif
	return secret;
}

void kdf(unsigned char *sharedSecret, uint8_t sslen, size_t *keydatalen, char *sharedinfo, uint8_t silen, unsigned char *key)
{
	// SEC 1: Elliptic Curve Cryptography, 3.6.1
#ifdef showmethod
	printf("USIM: kdf\n");
#endif
#ifdef measureAKMAfct2
	uint64_t y, z;
	y = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef testb
	puts("sharedSecret:");
	for (int i = 0; i < sslen; i++)
	{
		printf("%X", sharedSecret[i]);
	}
	printf("\n");
#endif

	int hashlen = sslen + silen + 4;
	int i;
	//	printf("%d : %d\n",hashlen, hashmaxlen);
	//	printf("%d : %d\n",sslen, silen);
	if ((hashlen) >= hashmaxlen)
	{
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

	for (i = 0; i < *keydatalen; i++)
	{
		// printf("i: %d %d\n",i,sslen);
		unsigned char hashinput[hashlen], md[32]; //= malloc(hashlen);
		for (int i = 0; i < sslen; i++)
		{
			hashinput[i] = sharedSecret[i];
		}
		// memcpy(hashinput, sharedSecret, sslen);
		// printf("hashinput: %s\n", hashinput);
		unsigned char tmp[5];
		sprintf(tmp, "%04x", counter);
		memcpy(hashinput + sslen, tmp, 4);
		// strncat(hashinput, sharedinfo, silen);

		// printf("hashinput: %s\n", hashinput);
		SHA256(hashinput, sizeof(hashinput), md);

		key[i] = md[0];
		counter++;
		// free(hashinput);
	}

#ifdef testb
	printf("Keydatalen: %u\n", *keydatalen);
	for (i = 0; i < *keydatalen; i++)
	{
		printf("%2x", key[i]);
	}
	puts("\n");
#endif

#ifdef measureAKMAfct2
	z = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	printf("USIM kdf Duration %lu ns\n", z - y);
#endif
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
			unsigned char *iv, unsigned char *ciphertext)
{
#ifdef showmethod
	printf("USIM: encrypt\n");
#endif
#ifdef measurefct
	uint64_t y, z;
	y = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();
#ifdef testb
	printf("plaintext length: %d\n", plaintext_len);
#endif
	/*
	 * Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits
	 */

	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
		handleErrors();

	/*
	 * Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;
	/*
	 * Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		handleErrors();
	ciphertext_len += len;
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

#ifdef measurefct
	z = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n", y);
	printf("B: %lu \n", z);
	printf("encrypt Duration %lu ns\n", z - y);
#endif
	return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
			unsigned char *iv, unsigned char *plaintext)
{
#ifdef showmethod
	printf("USIM: decrypt\n");
#endif
#ifdef measurefct
	uint64_t y, z;
	y = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();
	/*
	 * Initialise the decryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits
	 */
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
		handleErrors();
	/*
	 * Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary.
	 */
	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;
	/*
	 * Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
		handleErrors();
	plaintext_len += len;
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

#ifdef measurefct
	z = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n", y);
	printf("B: %lu \n", z);
	printf("decrypt Duration %lu ns\n", z - y);
#endif
	return plaintext_len;
}


int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, int iv_len, unsigned char *ciphertext,
                unsigned char *tag, int tag_len)
{
#ifdef showmethod
	printf("USIM: gcm_encrypt\n");
#endif
#ifdef measureAKMAfct2
	uint64_t y10,z10;
	y10=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
#ifdef testb
	printf("plaintext length: %d\n", plaintext_len);
#endif
    
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

#ifdef measureAKMAfct2
	z10=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	printf("USIM gcm_encrypt Duration %lu ns\n",z10-y10);
#endif
    return ciphertext_len;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *tag, int tag_len, unsigned char *key, unsigned char *iv,
                int iv_len, unsigned char *plaintext)
{
#ifdef showmethod
	printf("USIM: gcm_decrypt\n");
#endif
#ifdef measureAKMAfct2
	uint64_t y10,z10;
	y10=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

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
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
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
#ifdef measureAKMAfct2
	z10=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	printf("USIM gcm_decrypt Duration %lu ns\n",z10-y10);
#endif
    return plaintext_len;
}


void get_SUCI(suci_t *suci)
{
#ifdef showmethod
	printf("USIM: get_SUCI\n");
#endif
#ifdef measurefct
	uint64_t y, z;
	y = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	// create Keypair & get sharedsecret
	unsigned char *sharedSecret;
	unsigned char key[128], suci_tmp[128];
	size_t secretlen, keylen = 128, cipherlen;
#ifdef measureAKMAfct
	uint64_t y2,z2;
	y2=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	sharedSecret = getSharedSecret(&secretlen, suci);
#ifdef measureAKMAfct
	z2=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	printf("UE getSharedSecret Duration %lu ns\n",z2-y2);
#endif
	printf("USIM print sharedSecret with UDM:");
	for (int i = 0; i < secretlen; i++)
	{
		printf("%02x", sharedSecret[i]);
	}
	printf("\n");
	printf("USIM print suci->ecc_pub_key:");
	for (int i = 0; i < sizeof(suci->ecc_pub_key); i++)
	{
		printf("%02x", suci->ecc_pub_key[i]);
	}
	printf("\n");

#ifdef testb
	puts("shared Secret:");
	for (int i = 0; i < secretlen; i++)
	{
		printf("%X", sharedSecret[i]);
	}
	puts("\n");
	printf("secretlen: %d\n", secretlen);
#endif
	// get key

	kdf(sharedSecret, secretlen, &keylen, NULL, 0, &key);

	// encrypt
	unsigned char *supi_tmp;
#ifdef testb
	printf("SUPI.msin size: %d\n", sizeof(supi.msin));
	for (int i = 0; i < sizeof(supi.msin); i++)
	{
		printf("%x", supi.msin[i]);
	}
	printf("\n");
#endif
	supi_tmp = (unsigned char *)supi.msin;
	// TODO: generated key not used, instead fixed sharedsecret
#ifdef measureAKMAfct
	uint64_t y1,z1;
	y1=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	cipherlen = encrypt(supi_tmp, sizeof(supi.msin), key, NULL, suci_tmp);
#ifdef measureAKMAfct
	z1=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("UE encrypt supi Duration %lu ns\n",z1-y1);
#endif

#ifdef DebugAkmaInfo
	printf("Ciphertext suci_tmp[%d] is:\n", cipherlen);
	BIO_dump_fp(stdout, (const char *)suci_tmp, cipherlen);
#endif
	//	printf("SUCI.msin:");
	for (int i = 0; i < cipherlen; i++)
	{
		//		printf("%x",suci_tmp[i]);
		suci->msin[i] = (uint8_t)suci_tmp[i];
	}
	//	printf("\n");
#ifdef DebugAkmaInfo
	printf("\n==============supi->mcc_mnc====================\n");
	for (int i = 0; i < sizeof(supi.mcc_mnc); i++)
	{
		printf("%02x", supi.mcc_mnc[i]);
	}
	printf("\n==============supi->mcc_mnc====================\n");

	printf("\n==============supi->msin====================\n");
	for (int i = 0; i < sizeof(supi.msin); i++)
	{
		printf("%02x", supi.msin[i]);
	}
	printf("\n==============supi->msin====================\n");
#endif
	// memcpy(suci->msin, suci_tmp, 5);
	// for (int i = 0; i < sizeof(suci->msin); i++)
	// {
	// 	//		printf("%x",suci->msin[i]);
	// }
	//	printf("\n");
	// memcpy(suci->mcc_mnc, supi.mcc_mnc, 3);
	for (int i = 0; i < sizeof(suci->mcc_mnc); i++)
	{
		suci->mcc_mnc[i] = supi.mcc_mnc[i];
		//		printf("%x",suci->mcc_mnc[i]);
	}
	//  	printf("\n");
	// suci_tmp to suci_t

#ifdef measurefct
	z = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n", y);
	printf("B: %lu \n", z);
	printf("get_Suci Duration %lu ns\n", z - y);
#endif
}
int autnIsAccepted(uint8_t autn[16], uint8_t rand[16])
{
#ifdef showmethod
	printf("USIM: authIsAccepted\n");
#endif
#ifdef measurefct
	uint64_t y, z;
	y = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	uint8_t amf[2] = {0x80, 0x00};
	uint8_t mac_a[8], mac_p[8]; // MAC from AUTN and Proving-MAC
	uint8_t ak[6];
	uint8_t res[8], ck[16], ik[16];

	// Check SQN
	//  Compute AK and extract SQN
	f2345(key_k, rand, res, ck, ik, ak);
	uint8_t sqn[6];

	for (int i = 0; i < 6; i++)
	{
		sqn[i] = autn[i] ^ ak[i];
	}

	for (int i = 5; i >= 0; i--)
	{
		if (sqn[i] < sqn_ue[i])
		{
			printf("SQN not accepted");
			return 0;
		}
	}

	// Check MAC
	// Extract MAC from AUTN

	for (int i = 8; i < 16; i++)
	{
		mac_a[i - 8] = autn[i];
	}
#ifdef test
	printf("\t MAC_a: ");
	for (int i = 0; i < 8; i++)
	{
		printf("%x", mac_a[i]);
	}
	printf("\n");
#endif
	f1(key_k, rand, sqn, amf, &mac_p);
#ifdef test
	printf("\t MAC_p: ");
	for (int i = 0; i < 8; i++)
	{
		printf("%x", mac_p[i]);
	}
	printf("\n");
	printf("%d\n", memcmp(mac_a, mac_p, 8));
#endif
	if (memcmp(mac_a, mac_p, 8) != 0)
	{
		printf("MAC not accepted");
		return 0;
	}

#ifdef testb
	printf("USIM: Autn\n");
	printf("\t AK: ");
	for (int i = 0; i < 6; i++)
	{
		printf("%x", ak[i]);
	}
	printf("\n");
	printf("\t K: ");
	for (int i = 0; i < SIZE_K; i++)
	{
		printf("%x", key_k[i]);
	}
	printf("\n");
	printf("\t SQN: ");
	for (int i = 0; i < 6; i++)
	{
		printf("%x", sqn[i]);
	}
	printf("\n");
#endif

#ifdef measurefct
	z = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n", y);
	printf("B: %lu \n", z);
	printf("autnIsAccepted Duration %lu ns\n", z - y);
#endif
	return 1;
}

void computeRES(uint8_t autn[16], uint8_t rand[16], uint8_t res[8], uint8_t ck[16], uint8_t ik[16])
{
#ifdef showmethod
	printf("USIM: computeRes\n");
#endif
#ifdef measurefct
	uint64_t y, z;
	y = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	uint8_t ak[6];
	f2345(key_k, rand, res, ck, ik, ak);
#ifdef testb
	printf("USIM: Autn\n");
	printf("\t AK: ");
	for (int i = 0; i < 6; i++)
	{
		printf("%x", ak[i]);
	}
	printf("\n");
	printf("\t IK: ");
	for (int i = 0; i < 16; i++)
	{
		printf("%x", ik[i]);
	}
	printf("\n");
	printf("\t CK: ");
	for (int i = 0; i < 16; i++)
	{
		printf("%x", ck[i]);
	}
	printf("\n");
	printf("\t RES: ");
	for (int i = 0; i < 8; i++)
	{
		printf("%x", res[i]);
	}
	printf("\n");

#endif

#ifdef measurefct
	z = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n", y);
	printf("B: %lu \n", z);
	printf("computeRES Duration %lu ns\n", z - y);
#endif
}
/*
sn_name_t *sn_name : input
uint8_t *rand : input
uint8_t *kausf : output
*/
void derive_Kausf(sn_name_t *sn_name, uint8_t *rand, uint8_t *kausf)
{

#ifdef showAKMAmethod
	printf("USIM: derive_Kausf\n");
#endif
	// #ifdef measureAKMAfct
	// 	uint64_t a,b;
	// 	a=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// #endif

#ifdef DebugAkmaInfo
	printf("\nUIM print key: ");
	for (int i = 0; i < sizeof(key_k); i++)
	{
		printf("%02x", key_k[i]);
	}
	printf("\n");

	printf("\nUIM print rand: ");
	for (int i = 0; i < 16; i++)
	{
		printf("%02x", rand[i]);
	}
	printf("\n");
#endif
	// K_ausf derivation function (TS33.501, Annex A.2)
	uint8_t ak[6];
	uint8_t res[8], ck[16], ik[16];
	f2345(key_k, rand, res, ck, ik, ak);
#ifdef DebugAkmaInfo
	printf("\nUIM print res: ");
	for (int i = 0; i < sizeof(res); i++)
	{
		printf("%02x", res[i]);
	}
	printf("\n");
	printf("\nUIM print ck: ");
	for (int i = 0; i < sizeof(ck); i++)
	{
		printf("%02x", ck[i]);
	}
	printf("\n");
	printf("\nUIM print ik: ");
	for (int i = 0; i < sizeof(ik); i++)
	{
		printf("%02x", ik[i]);
	}
	printf("\n");
	printf("\nUIM print ak: ");
	for (int i = 0; i < sizeof(ak); i++)
	{
		printf("%02x", ak[i]);
	}
	printf("\n");
	printf("\nUIM print sn_name: ");
	printf("%s\n", sn_name);
	for (int i = 0; i < SIZE_SN_NAME; i++)
	{
		printf("%02x", (*sn_name)[i]);
	}
	printf("\n");
	printf("\nUIM print sqn_ue: ");
	for (int i = 0; i < sizeof(sqn_ue); i++)
	{
		printf("%02x", sqn_ue[i]);
	}
	printf("\n");
#endif

	uint8_t fc = 0x6a;
	char pn[SIZE_SN_NAME + 6];
	uint16_t ln[2];
	for (int i = 0; i < SIZE_SN_NAME; i++)
	{
		pn[i] = (*sn_name)[i];
	}

#ifdef DebugAkmaInfo
	printf("\nUIM print pn: ");
	printf("%s\n", pn);
	for (int i = 0; i < SIZE_SN_NAME; i++)
	{
		printf("%02x", pn[i]);
	}
	printf("\n");
#endif

	ln[0] = SIZE_SN_NAME;
	for (int i = 0; i < 6; i++)
	{
		pn[ln[0] + i] = sqn_ue[i] ^ ak[i];
	}		   // SQN XOR AK
	ln[1] = 6; // Length of SQN XOR AK

#ifdef DebugAkmaInfo
	printf("\nUIM print ln: ");
	for (int i = 0; i < sizeof(ln); i++)
	{
		printf("%02x", ln[i]);
	}
	printf("\n");

	printf("\nUIM print key_k(%d): ", SIZE_K);
	for (int i = 0; i < sizeof(key_k); i++)
	{
		printf("%02x", key_k[i]);
	}
	printf("\n");
	printf("\nUIM print fc: ");
	for (int i = 0; i < sizeof(fc); i++)
	{
		printf("%02x", fc);
	}
	printf("\n");
	printf("\nUIM print pn: ");
	for (int i = 0; i < sizeof(pn); i++)
	{
		printf("%02x", pn[i]);
	}
	printf("\n");
	printf("\nUIM print ln: ");
	for (int i = 0; i < sizeof(ln); i++)
	{
		printf("%02x", ln[i]);
	}
	printf("\n");
#endif

	genericKeyDerivation(key_k, SIZE_K, fc, (uint8_t *)pn, ln, 2, kausf);

	// #ifdef measureAKMAfct
	// 	b=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// 	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	// 	// printf("A: %lu \n",a);
	// 	// printf("B: %lu \n",b);
	// 	printf("UE step 3a derive Kausf Duration %lu ns\n",b-a);
	// #endif
}

/*
EVP_PKEY *pkey: must use EVP_PKEY_new() to allocate an empty EVP_PKEY structure before call
unsigned char * pubkey: store public key(in HEX format) after call, cannot be NULL
size_t *pubkey_len: store public key size
*/

void getECKey(EVP_PKEY *pkey, unsigned char *pubkey, size_t *pubkey_len)
{

	EVP_PKEY_CTX *kctx;
	EVP_PKEY_CTX *pctx;
	EVP_PKEY *peerkey = NULL, *params = NULL;
	EC_KEY *eckey = NULL;
	const EC_POINT *ecpoint = NULL;
	BN_CTX *bn_ctx;
	EC_GROUP *ecgroup = NULL;

	/* Create the context for parameter generation */
	if (NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)))
		handleErrors();

	/* Initialise the parameter generation */
	if (1 != EVP_PKEY_paramgen_init(pctx))
		handleErrors();

	/* We're going to use the ANSI X9.62 Prime 256v1 curve */
	if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID))
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
#ifdef measureAKMAfct2
	uint64_t y0,z0;
	y0=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	if (1 != EVP_PKEY_keygen(kctx, &pkey))
		handleErrors();
#ifdef measureAKMAfct2
	z0=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	printf("USIM EVP_PKEY_keygen Duration %lu ns\n",z0-y0);
#endif
	// if (1 != EVP_PKEY_generate(kctx, &pkey)) handleErrors();

	if (NULL == (eckey = EVP_PKEY_get1_EC_KEY(pkey)))
		handleErrors();

	if (NULL == (ecpoint = EC_KEY_get0_public_key(eckey)))
		handleErrors();

	if (NULL == (ecgroup = EC_GROUP_new_by_curve_name(NID)))
		handleErrors();

	if (NULL == (bn_ctx = BN_CTX_new()))
		handleErrors();

	(*pubkey_len) = EC_POINT_point2oct(ecgroup, ecpoint, EC_GROUP_get_point_conversion_form(ecgroup), pubkey, 1024, bn_ctx);
	if ((*pubkey_len) <= 0)
	{
		handleErrors();
	}
#ifdef DebugAkmaInfo
	printf("print pubkey(%d): \n", (*pubkey_len));
	BIO_dump_fp(stdout, (const char *)pubkey, (*pubkey_len));
#endif
	BN_CTX_free(bn_ctx);
	EC_POINT_free(ecpoint);
	EC_KEY_free(eckey);
	EVP_PKEY_free(params);
	EVP_PKEY_free(peerkey);
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_CTX_free(kctx);
}

/*
EVP_PKEY *pkey: must use getECKey()  before call
unsigned char * peer_pubkey: the public key which peer generate
size_t *secret_len: store shared key size
return value: shared key, this function will allocate the memory for it.
*/
unsigned char *getSharedKey(EVP_PKEY *pkey, unsigned char *peer_pubkey, size_t *secret_len)
{

	EVP_PKEY_CTX *ctx;
	EC_POINT *peer_point;
	EC_KEY *peer_eckey;

	EC_GROUP *peer_ecgroup;
	EVP_PKEY *peer_pkey;

	unsigned char *sharedSecret;

	// ecgroup = EC_GROUP_new_by_curve_name(NID);
	if (NULL == (peer_eckey = EC_KEY_new_by_curve_name(NID)))
		handleErrors();

	peer_ecgroup = EC_KEY_get0_group(peer_eckey);

	if (NULL == (peer_point = EC_POINT_new(peer_ecgroup)))
		handleErrors();

	if (1 != EC_POINT_oct2point(peer_ecgroup, peer_point, peer_pubkey, 65, NULL))
		handleErrors();

	if (1 != EC_KEY_set_public_key(peer_eckey, peer_point))
		handleErrors();

	if (NULL == (peer_pkey = EVP_PKEY_new()))
		handleErrors();

	if (1 != EVP_PKEY_set1_EC_KEY(peer_pkey, peer_eckey))
		handleErrors();
	/* To serialize the public key:

	Pass the EVP_PKEY to EVP_PKEY_get1_EC_KEY() to get an EC_KEY.
	Pass the EC_KEY to EC_KEY_get0_public_key() to get an EC_POINT.
	Pass the EC_POINT to EC_POINT_point2oct() to get octets, which are just unsigned char *.
	 */
	if (NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL)))
		handleErrors();

	/* Initialise */
	if (1 != EVP_PKEY_derive_init(ctx))
		handleErrors();

	/* Provide the peer public key */
	if (1 != EVP_PKEY_derive_set_peer(ctx, peer_pkey))
		handleErrors();

	/* Determine buffer length for shared secret */
	// if(1 != EVP_PKEY_derive(ctx, NULL, secretLength)) handleErrors();
	EVP_PKEY_derive(ctx, NULL, secret_len);

	/* Create the buffer */
	if (NULL == (sharedSecret = OPENSSL_malloc(*secret_len)))
		handleErrors();

	/* Derive the shared secret */
	if (1 != EVP_PKEY_derive(ctx, sharedSecret, secret_len))
		handleErrors();

	EVP_PKEY_free(peer_pkey);
	EC_GROUP_free(peer_ecgroup);
	// EC_KEY_free(peer_eckey);
	EC_POINT_free(peer_point);
	// EVP_PKEY_CTX_free(ctx);

	return sharedSecret;
}

/*
unsigned char *a1: input, a1 is a random 
enc(U || a1) with PK_AF(AF RSA public key)
return the encrypted info with len bytes.
*/
unsigned char *getCT_UE_AF(unsigned char *a1, size_t a1_len, size_t *len)
{
#ifdef showAKMAmethod
    printf("USIM getCT_UE_AF \n");
#endif		
#ifdef measureAKMAfct2
	uint64_t y10,z10;
	y10=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	
	size_t CT_UE_AF_len = sizeof(U) + a1_len;
	unsigned char CT_UE_AF[CT_UE_AF_len];
	memcpy(CT_UE_AF, U, sizeof(U));
	memcpy(CT_UE_AF + sizeof(U), a1, a1_len);

#ifdef DebugAkmaInfo
	printf("Message to encrypt to CT_UE_AF: ");
	for (int i = 0; i < sizeof(CT_UE_AF); i++)
	{
		printf("%02x", CT_UE_AF[i]);
	}
	printf("\n");
#endif
	int encrypt_len;

	unsigned char *Enc_CT_UE_AF;

	EVP_PKEY_CTX *enc_ctx = NULL;
	if (NULL == (enc_ctx = EVP_PKEY_CTX_new(s_AF_pkey, NULL)))
	{
		handleErrors();
	}
	if (EVP_PKEY_encrypt_init(enc_ctx) <= 0)
	{
		handleErrors();
	}
	// Any algorithm specific control operations can be performec now before
	if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
	{
		handleErrors();
	}
#ifdef DebugAkmaInfo
	printf("Going to encrypt CT_UE_AF: (len:%d) is:\n", CT_UE_AF_len);
	BIO_dump_fp(stdout, (const char *)CT_UE_AF, CT_UE_AF_len);
#endif
	// Determine the size of the output
	if (EVP_PKEY_encrypt(enc_ctx, NULL, len, CT_UE_AF, CT_UE_AF_len) <= 0)
	{
		handleErrors();
	}
#ifdef DebugAkmaInfo
	printf("Determined ciphertext to be of length: %d) is:\n", *len);
#endif
	Enc_CT_UE_AF = OPENSSL_malloc(*len);

	if (EVP_PKEY_encrypt(enc_ctx, Enc_CT_UE_AF, len, CT_UE_AF, CT_UE_AF_len) <= 0)
	{
		handleErrors();
	}
#ifdef measureAKMAfct2
	z10=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	printf("UE PKEnc step 6 getCT_UE_AF Duration %lu ns\n",z10-y10);
#endif

#ifdef DebugAkmaInfo
	printf("Encrypted ciphertext (len:%d) is:\n", *len);
	BIO_dump_fp(stdout, (const char *)Enc_CT_UE_AF, *len);
#endif
	return Enc_CT_UE_AF;

}

