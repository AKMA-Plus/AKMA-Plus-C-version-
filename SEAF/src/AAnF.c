#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include "AAnF.h"
#include "UDM.h"
#include "ffunction.h"
#include "genericFunctions.h"
#include "sidf.h"

static k_akma_t g_k_akma;
static a_kid_t g_a_kid;
static supi_t g_supi;
static af_id_t g_af_id;
static k_af_t g_k_af;
static gpsi_t g_gpsi;

#define akma_pair_max_size 10000
static size_t akma_pair_index = 0;
static akma_pair_t akma_pair_db[akma_pair_max_size];

extern size_t PK_AAnF_len; 
extern char *PK_AAnF;
extern size_t SK_AAnF_len;                // Length of private key
extern char *SK_AAnF;       // RSA Private key

#define RSA_KEY_LENGTH 1024
static EVP_PKEY *s_RSA_pkey;


/*
generate RSA key

store public key in s_RSA_PK_AF;
store EVP_PKEY in s_RSA_pkey
*/


void generateRSAKey2() {
#ifdef showAKMAmethod
    printf("AAnF generateRSAKey2 Generating RSA (%d bits) AF_keypair...\n", RSA_KEY_LENGTH);
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
    BIO *PK_AAnF_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(PK_AAnF_bio, s_RSA_pkey);
    
    PK_AAnF_len = BIO_pending(PK_AAnF_bio);
    PK_AAnF = malloc(PK_AAnF_len + 1);
    if (BIO_read(PK_AAnF_bio, PK_AAnF, PK_AAnF_len) <= 0)
    {
        handleErrors();
    }
    PK_AAnF[PK_AAnF_len] = '\0';

    BIO *SK_AAnF_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(SK_AAnF_bio, s_RSA_pkey, NULL, NULL, 0, NULL, NULL);

    SK_AAnF_len = BIO_pending(SK_AAnF_bio);
    SK_AAnF = malloc(SK_AAnF_len + 1);
    if (BIO_read(SK_AAnF_bio, SK_AAnF, SK_AAnF_len) <= 0)
    {
        handleErrors();
    }
    SK_AAnF[SK_AAnF_len] = '\0';

#ifdef DebugAkmaInfo
    printf("\nAAnF print pub_len = %d \n", PK_AAnF_len);
    printf("\n%s\n", PK_AAnF);
    printf("\nAAnF print prv_len = %d \n", SK_AAnF_len);
    printf("\n%s\n", SK_AAnF);
    // EVP_PKEY_CTX_free(rsa_ctx);  //it cannot free
    BIO_free(PK_AAnF_bio);
    BIO_free(SK_AAnF_bio);
    BN_free(exponent_bn);
#endif
}


void aanf_init() {

	generateRSAKey2();

}

/*
supi_t * supi : input
a_kid_t * a_kid : input
k_akma_t * k_akma : input
*/
void Naanf_AKMA_AnchorKey_Register_Request_AAnF(supi_t * supi, a_kid_t * a_kid, k_akma_t * k_akma)
{
#ifdef showAKMAmethod
    printf("AKMA step 4 (AUSF-->AAnF) Naanf_AKMA_AnchorKey_Register_Request_AAnF(supi, a_kid, k_akma) receive \n");
#endif

#ifdef CommCosts 
	int costLen = sizeof(supi_t) + sizeof(a_kid_t) + sizeof(k_akma_t);
	printf("\nAKMA step 4 (AUSF-->AAnF) AAnF receive message from AUSF (%d bytes)\n", costLen);
#endif

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
    g_supi = *supi;
    g_a_kid = *a_kid;
    g_k_akma = *k_akma;
#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("AAnF step 4 Duration %lu ns\n",z-y);
#endif

    Naanf_AKMA_AnchorKey_Register_Response_AAnF();


}

/*
supi_t * supi : input
a_kid_t * a_kid : input
k_akma_t * k_akma : input
*/
void Naanf_AKMA_AnchorKey_Register_Request_AAnF_2(akma_pair_t * p_akma_pair, size_t akma_pair_size)
{
#ifdef showAKMAmethod
    printf("AKMA step 4 (AUSF-->AAnF) Naanf_AKMA_AnchorKey_Register_Request_AAnF_2(akma_pair, akma_pair_size) receive \n");
#endif

#ifdef CommCosts 
	int costLen = sizeof(akma_pair_t) * akma_pair_size;
	printf("\nAKMA step 4 (AUSF-->AAnF) AAnF receive message from AUSF (%d bytes)\n", costLen);
#endif

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
    // g_supi = *supi;
    // g_a_kid = *a_kid;
    // g_k_akma = *k_akma;

	if(akma_pair_index + akma_pair_size >=akma_pair_max_size) {
		fprintf(stderr, "not enough space store p_akma_pair in akma_pair_db\n");
		fprintf(stderr, "akma_pair_index = %d, akma_pair_max_size=%d, akma_pair_size=%d\n", 
			akma_pair_index,
			akma_pair_max_size, 
			akma_pair_size
			);
        exit(1);
	}

	for(int i=0;i<akma_pair_size;i++) {
		akma_pair_db[akma_pair_index + i] = p_akma_pair[i];
	}
	akma_pair_index += akma_pair_size;

#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("AAnF step 4 akma+ Duration %lu ns\n",z-y);
#endif

    Naanf_AKMA_AnchorKey_Register_Response_AAnF();


}


/*
a_kid_t * a_kid input
k_akma_t *k_akma output
return value:
-1 not found
others index
*/

int Get_KAKMA(a_kid_t * a_kid, k_akma_t *p_k_akma)
{
#ifdef DebugAkmaInfo
	printf("*************Get_KAKMA start*************, akma_pair_index = %d\n", akma_pair_index);
#endif
	// (a_kid->username).a_tid;
	// (akma_pair_db[i]).a_kid.username.a_tid
	for (int i=0;i<akma_pair_index;i++) {
#ifdef DebugAkmaInfo
		printf("i=%d, (akma_pair_db[i]).a_kid.username.a_tid= ", i);
		for(int j=0;j<sizeof((akma_pair_db[i]).a_kid.username.a_tid);j++) {
			printf("%02x", ((akma_pair_db[i]).a_kid.username.a_tid)[j]);
		}
		printf("\n");
#endif
		if(strncmp((a_kid->username).a_tid, 
			(akma_pair_db[i]).a_kid.username.a_tid, 
			sizeof((a_kid->username).a_tid)) == 0)
		{
			(*p_k_akma) =  (akma_pair_db[i]).k_akma;
			return i;
		}
	}
	return -1;

}

void Naanf_AKMA_AnchorKey_Register_Response_AAnF(){
#ifdef showAKMAmethod
    printf("AKMA step 5 (AAnF-->AUSF) Naanf_AKMA_AnchorKey_Register_Response_AAnF() send \n");
#endif

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("AAnF step 5 Duration %lu ns\n",z-y);
#endif

#ifdef CommCosts 
	int costLen = 1;
	printf("\nAKMA step 5 (AAnF-->AUSF) AAnF send message to AUSF (%d bytes)\n", costLen);
#endif

}

void Naanf_AKMA_ApplicationKey_GetRequest_AAnF(a_kid_t * a_kid, af_id_t * af_id, 
		unsigned char *enc_CT_UE_AAnF, size_t enc_CT_UE_AAnF_len, unsigned char *CT_UE_AAnF_TAG, 
		unsigned char *buf, int *plen){
#ifdef showAKMAmethod
    printf("AKMA step 7 (AF-->AAnF) Naanf_AKMA_ApplicationKey_GetRequest_AAnF(A-KID, AF_ID) receive \n");
#endif

#ifdef DebugAkmaInfo
	print_akid(a_kid);
	printf("\n");
#endif

#ifdef measureAKMAfct
	uint64_t y1,z1;
	y1=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	int index = Get_KAKMA(a_kid, &g_k_akma);
	if(index < 0) {
		fprintf(stderr, "get k_akma from akma_pair_db error\n");
		exit(1);
	}
#ifdef measureAKMAfct
	z1=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	printf("AAnF step 7 akma+ Get_KAKMA add Duration %lu ns\n",z1-y1);
#endif

#ifdef DebugAkmaInfo
	printf("\n");
	printf("AAnF get k_akma->k_akma: ");
	for (int i = 0; i < 32; i++)
	{
		printf("%02x", g_k_akma.k_akma[i]);
	}
	printf("\n");
#endif

    g_a_kid = *a_kid;
    g_af_id = *af_id;

	/*
	step 8 to step 9
	*/
    Nudm_SDM_GetRequest_AAnF(&g_supi, &g_gpsi);

#ifdef DebugAkmaInfo
	printf("before Nudm_EventExposure_Subscribe_Request_AAnF input a_kid\n");
	print_akid(a_kid);
#endif
	Nudm_EventExposure_Subscribe_Request_AAnF(&g_a_kid);
    
    calc_KAF_from_KAKMA(&g_k_akma, &g_af_id, &g_k_af);

#ifdef measureAKMAfct
	uint64_t y2,z2;
	y2=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
    struct timeval k_af_exp;
    k_af_exp.tv_sec = 1;
    k_af_exp.tv_usec = 0;

	// decrypt enc_CT_UE_AAnF, i.e. a2
	unsigned char CT_UE_AAnF[BUFSIZ];
	// int CT_UE_AAnF_len = decrypt(enc_CT_UE_AAnF, enc_CT_UE_AAnF_len, g_k_af.k_af, 0, CT_UE_AAnF);
    int CT_UE_AAnF_len = gcm_encrypt(enc_CT_UE_AAnF, enc_CT_UE_AAnF_len, g_k_akma.k_akma, iv, IV_LEN, 
				CT_UE_AAnF, CT_UE_AAnF_TAG, TAG_SIZE);


#ifdef DebugAkmaInfo
    printf("AAnF print CT_UE_AAnF(%d):\n", CT_UE_AAnF_len);
	BIO_dump_fp(stdout, (const char *)CT_UE_AAnF, CT_UE_AAnF_len);

#endif

    /*
	CT_UE_AAnF = a2
	*/
	unsigned char a2[16];
	memcpy(a2, CT_UE_AAnF, 16);

	BIGNUM  * a2plus1_bn = BN_bin2bn(a2, 16, NULL);
#ifdef DebugAkmaInfo
	printf("AAnF print get a2:\n");
	BN_print_fp(stdout, a2plus1_bn);
	printf("\n");
#endif

	BN_add_word(a2plus1_bn, 1);

#ifdef DebugAkmaInfo
	printf("AAnF print after a2plus1_bn:\n");
	BN_print_fp(stdout, a2plus1_bn);
	printf("\n");
#endif
	unsigned char a2plus1[16];
	BN_bn2bin(a2plus1_bn, a2plus1);

#ifdef DebugAkmaInfo
	printf("AAnF print a2plus1 (len:%d) is:\n", sizeof(a2plus1));
	BIO_dump_fp(stdout, (const char *)a2plus1, sizeof(a2plus1));
#endif
	/*
	CT_AAnF_UE = a2plus1
	*/
	unsigned char CT_AAnF_UE[sizeof(a2plus1)];
	unsigned char CT_AAnF_UE_TAG[TAG_SIZE];
	memcpy(CT_AAnF_UE, a2plus1, sizeof(a2plus1));

#ifdef DebugAkmaInfo
	printf("CT_AAnF_UE (len:%d) is:\n", sizeof(CT_AAnF_UE));
	BIO_dump_fp(stdout, (const char *)CT_AAnF_UE, sizeof(CT_AAnF_UE));
#endif

	unsigned char SEnc_CT_AAnF_UE[BUFSIZ];
	int SEnc_CT_AAnF_UE_Len = gcm_encrypt(CT_AAnF_UE, sizeof(CT_AAnF_UE), g_k_akma.k_akma, iv, IV_LEN, 
				SEnc_CT_AAnF_UE, CT_AAnF_UE_TAG, TAG_SIZE);

#ifdef DebugAkmaInfo
	printf("encrypted SEnc_CT_AAnF_UE (len:%d) is:\n", SEnc_CT_AAnF_UE_Len);
	BIO_dump_fp(stdout, (const char *)SEnc_CT_AAnF_UE, SEnc_CT_AAnF_UE_Len);
	printf("CT_AAnF_UE_TAG (len:%d) is:\n", TAG_SIZE);
	BIO_dump_fp(stdout, (const char *)CT_AAnF_UE_TAG, TAG_SIZE);
#endif

//     unsigned char Res_AAnF[BUFSIZ];
//     unsigned int Res_AAnF_len = 0;
//     unsigned char Res_AAnF_sign[BUFSIZ];
//     unsigned int Res_AAnF_sign_len = 0;
//     ResAAnF_Sign(&g_af_id, CT_UE_AAnF, CT_UE_AAnF_len, 
//                 Res_AAnF, &Res_AAnF_len,
//                 Res_AAnF_sign, &Res_AAnF_sign_len);

// #ifdef DebugAkmaInfo
//     printf("after ResAAnF_Sign [%d]:\n", Res_AAnF_sign_len);
// 	BIO_dump_fp(stdout, (const char *)Res_AAnF_sign, Res_AAnF_sign_len);
// #endif
#ifdef measureAKMAfct
	z2=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
    printf("AAnF step 12 akma+ add Duration %lu ns\n",z2-y2);
#endif

    // Naanf_AKMA_ApplicationKey_GetResonse_AAnF(&g_k_af, &k_af_exp, &g_supi, 
    //         Res_AAnF, Res_AAnF_len,
    //         Res_AAnF_sign, Res_AAnF_sign_len, buf, plen);

    Naanf_AKMA_ApplicationKey_GetResonse_AAnF_2(&g_k_af, &k_af_exp, &g_supi, 
            SEnc_CT_AAnF_UE, SEnc_CT_AAnF_UE_Len, CT_AAnF_UE_TAG, buf, plen);

#ifdef measurefct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",y);
	printf("B: %lu \n",z);
	printf("Naanf_AKMA_ApplicationKey_GetRequest_AAnF Duration %lu ns\n",z-y);
#endif
#ifdef CommCosts
				printf("AKMA step 13 (AAnF-->AF) AAnf send message to AF(%d bytes)\n", (*plen));
#ifdef DebugAkmaInfo
				for (int i = 0; i < (*plen); i++)
				{
					printf("%02x", buf[i]);
				}
				printf("\n");
#endif
#endif
}

void Nudm_SDM_GetRequest_AAnF(supi_t * supi, gpsi_t * gpsi){
#ifdef showAKMAmethod
    printf("AKMA step 8 (AAnF-->UDM) Nudm_SDM_GetRequest_AAnF(supi_t) send \n");
#endif

#ifdef CommCosts 
	int costLen = sizeof(supi_t);
	printf("\nAKMA step 8 (AAnF-->UDM) AAnF send message to UDM (%d bytes)\n", costLen);
#endif

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("AAnF step 8 Duration %lu ns\n",z-y);
#endif

    //get gpsi from udm

    Nudm_SDM_GetRequest_UDM(supi, gpsi);

    
    Nudm_SDM_GetResponse_AAnF(gpsi);


}

/*
gpsi_t * gpsi: input
*/
void Nudm_SDM_GetResponse_AAnF(gpsi_t * gpsi){
#ifdef showAKMAmethod
    printf("AKMA step 9 (UDM-->AAnF) Nudm_SDM_GetResponse_AAnF(gpsi_t) receive \n");
#endif

#ifdef CommCosts 
	int costLen = sizeof(gpsi_t);
	printf("\nAKMA step 9 (UDM-->AAnF) AAnF receive message from UDM (%d bytes)\n", costLen);
#endif

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("AAnF step 9 Duration %lu ns\n",z-y);
#endif



#ifdef DebugAkmaInfo
    printf("AAnF print gpsi\n");
    printf("\t gpsi:");
    for(int i=0;i<sizeof(gpsi->gpsi);i++) {
        printf("%02x", (gpsi->gpsi)[i]);

    }
    printf("\n");
#endif


}

void Nudm_EventExposure_Subscribe_Request_AAnF(a_kid_t * a_kid){
#ifdef showAKMAmethod
    printf("AKMA step 10 (AAnF-->UDM) Nudm_EventExposure_Subscribe_Request_AAnF(a_kid_t) send \n");
#endif

#ifdef CommCosts 
	int costLen = sizeof(a_kid_t);
	printf("\nAKMA step 10 (AAnF-->UDM) AAnF send message to UDM (%d bytes)\n", costLen);
#endif

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("AAnF step 10 Duration %lu ns\n",z-y);
#endif

	//get roaming,New_servingPlmn,accessType from udm
	unsigned char roaming[1024];
	unsigned char New_servingPlmn[1024];
	unsigned char accessType[1024];
	memset(roaming, 0x00, sizeof(roaming));
	memset(New_servingPlmn, 0x00, sizeof(New_servingPlmn));
	memset(accessType, 0x00, sizeof(accessType));
#ifdef DebugAkmaInfo
	printf("Nudm_EventExposure_Subscribe_Request_AAnF input a_kid\n");
	print_akid(a_kid);
#endif
	/*
	step 10
	*/
    Nudm_EventExposure_Subscribe_Request_UDM(a_kid, roaming, New_servingPlmn, accessType);
	
    /*
	step 11
	*/
    Nudm_EventExposure_Subscribe_Response_AAnF(roaming, New_servingPlmn, accessType);


}

/*
gpsi_t * gpsi: input
*/
void Nudm_EventExposure_Subscribe_Response_AAnF(
	unsigned char *roaming, unsigned char *New_servingPlmn, unsigned char *accessType){
#ifdef showAKMAmethod
    printf("AKMA Step 11 (UDM-->AAnF) Nudm_EventExposure_Subscribe_Response_AAnF(roaming, New_servingPlmn, accessType) receive \n");
#endif

#ifdef CommCosts 
	int costLen = strlen(roaming) + strlen(New_servingPlmn) + strlen(accessType);
	printf("\nAKMA Step 11 (UDM-->AAnF) AAnF receive message from UDM (%d bytes)\n", costLen);
#endif

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("AAnF step 11 Duration %lu ns\n",z-y);
#endif



#ifdef DebugAkmaInfo
    printf("AAnF print roaming: %s\n", roaming);
	printf("AAnF print New_servingPlmn: %s\n", New_servingPlmn);
	printf("AAnF print accessType: %s\n", accessType);
#endif
}

// k_akma: input
// af_id: input
// k_af: output
static void calc_KAF_from_KAKMA(k_akma_t *k_akma, af_id_t *af_id, k_af_t *k_af){
#ifdef showAKMAmethod
    printf("AKMA step 12 (AAnF calc) calc_KAF_from_K_AKMA(k_akma_t,af_id_t,k_af_t) begin \n");
#endif

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

    int SIZE_K_AKMA = 32;
	int SIZE_K_ATID = 5;
	uint8_t fc = 0x82;
	char pn[SIZE_K_ATID+sizeof(af_id_t)];
	memcpy(pn, "AF_ID", SIZE_K_ATID);
	uint16_t ln[1];
	ln[0] = sizeof(af_id_t);
	memcpy(pn+SIZE_K_ATID, af_id->fqdn, sizeof(af_id->fqdn));
	memcpy(pn+SIZE_K_ATID+sizeof(af_id->fqdn), af_id->uaid, sizeof(af_id->uaid));

	genericKeyDerivation(k_akma->k_akma,SIZE_K_AKMA,fc,(uint8_t*)pn,ln,1,k_af->k_af);
    
#ifdef DebugAkmaInfo
	printf("\n");
	printf("AAnF calc_KAF_from_KAKMA print k_af->k_af: ");
	for(int i=0;i<sizeof(k_af->k_af);i++){
		printf("%02x",(k_af->k_af)[i]);
	}
	printf("\n");
#endif

#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("AAnF step 12 Duration %lu ns\n",z-y);
#endif
}

/*
Sign ResAAnF with s_RSA_pkey
ResAAnF = af_id + CT_UE_AAnF(i.e. a2)
af_id_t *af_id: input
unsigned char *CT_UE_AAnF: input
int CT_UE_AAnF_len: input

unsigned char *Res_AAnF: output
unsigned int *pRes_AAnF_len: output
unsigned char *Res_AAnF_sign: output
unsigned int *pRes_AAnF_sign_len: output
*/
void ResAAnF_Sign(af_id_t *af_id, unsigned char *CT_UE_AAnF, int CT_UE_AAnF_len, 
        unsigned char *Res_AAnF, unsigned int *pRes_AAnF_len,
        unsigned char *Res_AAnF_sign, unsigned int *pRes_AAnF_sign_len) {


    int offset = 0;
    memcpy(Res_AAnF + offset, CT_UE_AAnF, CT_UE_AAnF_len);
    offset += CT_UE_AAnF_len;

    memcpy(Res_AAnF + offset, af_id->fqdn, sizeof(af_id->fqdn));
    offset += sizeof(af_id->fqdn);

    memcpy(Res_AAnF + offset, af_id->uaid, sizeof(af_id->uaid));
    offset += sizeof(af_id->uaid);

    (*pRes_AAnF_len) = offset;

    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(mdctx);
    if(!EVP_SignInit_ex(mdctx, EVP_sha256(), NULL))
    {  
        printf("EVP_SignInit_ex err\n");  
        handleErrors();
        return;  
    }  
    if(!EVP_SignUpdate(mdctx, Res_AAnF, (*pRes_AAnF_len)))
    {  
        handleErrors();
        return;  
    }  
    if(!EVP_SignFinal(mdctx,Res_AAnF_sign,pRes_AAnF_sign_len,s_RSA_pkey))
    {  
        printf("EVP_SignFinal err\n");  
        handleErrors();
        return;  
    }
#ifdef DebugAkmaInfo
    printf("Res_AAnF sign value is[%d]:\n", (*pRes_AAnF_sign_len));
	BIO_dump_fp(stdout, (const char *)Res_AAnF_sign, (*pRes_AAnF_sign_len));
    printf("\n");    
#endif 
    EVP_MD_CTX_free(mdctx);  

}

void Naanf_AKMA_ApplicationKey_GetResonse_AAnF(k_af_t *k_af, struct timeval *k_af_exp, supi_t * supi, 
    unsigned char *Res_AAnF, int Res_AAnF_len, 
    unsigned char *Res_AAnF_sign, int Res_AAnF_sign_len, 
    unsigned char *buf, int *plen){
#ifdef showAKMAmethod
    printf("AKMA step 13 (AAnF-->AF) Naanf_AKMA_ApplicationKey_GetResonse_AAnF(k_af, k_af_exp, supi) send \n");
#endif

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

    int offset = 0;
    // buf = k_af_t + timeval + Res_AAnF_len(4 Bytes) + Res_AAnF + Res_AAnF_sign
    memcpy(buf + offset, k_af->k_af, sizeof(k_af->k_af));
    offset += sizeof(k_af->k_af);

    memcpy(buf + offset, k_af_exp, sizeof(struct timeval));
    offset += sizeof(struct timeval);

    // memcpy(buf + offset, supi->mcc_mnc, sizeof(supi->mcc_mnc));
    // offset += sizeof(supi->mcc_mnc);

    // memcpy(buf + offset, supi->msin, sizeof(supi->msin));
    // offset += sizeof(supi->msin);
#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("AAnF step 13 Duration %lu ns\n",z-y);
#endif

#ifdef measureAKMAfct
	uint64_t y2,z2;
	y2=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
    char str_Res_AAnF_len[5];
    sprintf(str_Res_AAnF_len, "%04d", Res_AAnF_len);
    memcpy(buf + offset, str_Res_AAnF_len, 4);
    offset += 4;

    memcpy(buf + offset, Res_AAnF, Res_AAnF_len);
    offset += Res_AAnF_len;

    memcpy(buf + offset, Res_AAnF_sign, Res_AAnF_sign_len);
    offset += Res_AAnF_sign_len;

    *plen = offset;

#ifdef measureAKMAfct
	z2=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("AAnF step 13 akma+ add Duration %lu ns\n",z2-y2);
#endif

}

void Naanf_AKMA_ApplicationKey_GetResonse_AAnF_2(k_af_t *k_af, struct timeval *k_af_exp, supi_t * supi, 
    unsigned char *CT_AAnF_UE, int CT_AAnF_UE_Len, unsigned char *CT_AAnF_UE_TAG,
    unsigned char *buf, int *plen){
#ifdef showAKMAmethod
    printf("AKMA step 13 (AAnF-->AF) Naanf_AKMA_ApplicationKey_GetResonse_AAnF(k_af, k_af_exp, supi) send \n");
#endif

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

    int offset = 0;
    // buf = k_af_t + timeval + CT_AAnF_UE_Len(4 bytes) + CT_AAnF_UE + CT_AAnF_UE_TAG(2 bytes)
    memcpy(buf + offset, k_af->k_af, sizeof(k_af->k_af));
    offset += sizeof(k_af->k_af);

    memcpy(buf + offset, k_af_exp, sizeof(struct timeval));
    offset += sizeof(struct timeval);

    // memcpy(buf + offset, supi->mcc_mnc, sizeof(supi->mcc_mnc));
    // offset += sizeof(supi->mcc_mnc);

    // memcpy(buf + offset, supi->msin, sizeof(supi->msin));
    // offset += sizeof(supi->msin);
#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("AAnF step 13 Duration %lu ns\n",z-y);
#endif

#ifdef measureAKMAfct
	uint64_t y2,z2;
	y2=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
    sprintf(buf + offset, "%04d", CT_AAnF_UE_Len);
	offset += 4;

	memcpy(buf + offset, CT_AAnF_UE, CT_AAnF_UE_Len);
	offset += CT_AAnF_UE_Len;

	memcpy(buf + offset, CT_AAnF_UE_TAG, TAG_SIZE);
	offset += TAG_SIZE;

    *plen = offset;

#ifdef measureAKMAfct
	z2=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("AAnF step 13 akma+ add Duration %lu ns\n",z2-y2);
#endif

}

// void Application_Session_Establishment_Response_AAnF(){
//     printf("AKMA Step (AF-->UE) Application_Session_Establishment_Response_AAnF \n");
// }

