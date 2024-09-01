/*
 ============================================================================
 Name        : UE.c

 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include "identifier.h"
#include "USIM.h"
#include "genericFunctions.h"
#include "ffunction.h"
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#define CL_PORT	50000
#define SV_PORT 50001
#define AF_PORT 50002
#define BUFSIZE 2048

#include "defs.h"

sn_name_t sn_name = "5G:NTNUnet";

static void calc_Kakma_from_KAUSF(k_ausf_t *k_ausf, supi_t *supi, k_akma_t *k_akma);
static void calc_AKID_from_KAUSF(k_ausf_t *k_ausf, supi_t *supi, a_kid_t *a_kid);
static void calc_KAF_from_KAKMA(k_akma_t *k_akma, af_id_t *af_id, k_af_t *k_af);
void Application_Session_Establishment_Request_UE(a_kid_t *a_kid);
void Application_Session_Establishment_Response_UE();
void getCurrentDate(unsigned *date);
static void calc_Kakma_from_KAUSF_2(k_ausf_t *k_ausf, supi_t *supi,
									   int counter, unsigned char *date, k_akma_t *k_akma);
static void calc_AKID_from_KAUSF_2(k_ausf_t *k_ausf, supi_t *supi,
									  int counter, unsigned char *date, a_kid_t *a_kid);

static k_akma_t g_k_akma;
static a_kid_t g_a_kid;
static rid_t g_rid;
static supi_t g_supi;
static af_id_t g_af_id;
static k_af_t g_k_af;
static k_af_prime_t g_k_af_prime;


unsigned char PK_AF[BUFSIZ];
size_t PK_AF_len;

// AF ECDSA key
EVP_PKEY *s_AF_ECDSA_pkey=NULL;
char *AF_ECDSA_Pubkey=NULL; // Public key
size_t AF_ECDSA_Pubkey_len;                // Length of public key

// AF ECIES key
char *AF_ECIES_Pubkey=NULL; // Public key
size_t AF_ECIES_Pubkey_len;                // Length of public key

// UE ECIES key
EVP_PKEY *s_UE_ECIES_pkey=NULL;
char *UE_ECIES_Pubkey=NULL; // Public key
size_t UE_ECIES_Pubkey_len;                // Length of public key
char UE_AF_ECIES_Shared_Secret_Key[128]; 
size_t UE_AF_ECIES_Shared_Secret_Key_len=128;   

// unsigned char PK_AAnF[1024];
// size_t PK_AAnF_len;

unsigned char U[65];
EVP_PKEY *p_u;
size_t U_len = 0;
#define IV_LEN  12    /*  96 bits */
#define TAG_SIZE 2
static const uint8_t iv[IV_LEN]           = { 0 };

static void calc_XRESstar(uint8_t XRESstar[32], sn_name_t sn_name, uint8_t rand[16], uint8_t res[8], uint8_t ck[16],uint8_t ik[16]){
#ifdef showmethod
	printf("UDM: getXRESstar\n");
#endif
#ifdef measurefct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	// RES* and XRES* derivation function (TS33.501, Annex A.4)
	int n = 3, rand_size=16, res_size=8;

	uint8_t fc = 0x6b;
	char pn[SIZE_SN_NAME+rand_size+res_size];
	uint16_t ln[n];
	for(int i=0; i<SIZE_SN_NAME;i++){
		pn[i] = sn_name[i];
	}
	ln[0] = SIZE_SN_NAME;

	for(int i=0; i<rand_size;i++){
		pn[ln[0]+i] = rand[i];
	}
	ln[1] = rand_size;

	for(int i=0; i<res_size;i++){
		pn[ln[0]+ln[1]+i] = res[i];
	}
	ln[2] = res_size;

	uint8_t tmp_key[SIZE_K];
	for(int i=0;i< 8;i++){
		tmp_key[i]=ck[i];
	}
	for(int i=0;i< 8;i++){
		tmp_key[8+i]=ik[i];
	}

	genericKeyDerivation(tmp_key,sizeof(tmp_key),fc,pn,ln,n,XRESstar);

#ifdef measurefct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",y);
	printf("B: %lu \n",z);
	printf("calc_HXRESstar Duration %lu ns\n",z-y);
#endif
	return;
}

static int getRand(size_t size)
{
	srand((unsigned)time(NULL));
	int rand_i = rand() % size;
	return rand_i;
}


int main(void) {

	initUSIM(&g_supi);


	p_u = EVP_PKEY_new();
	getECKey(p_u, U, &U_len);

	unsigned char a1[16];
	memset(a1, 0xFF, sizeof(a1));
	RAND_bytes(a1, sizeof(a1));
#ifdef DebugAkmaInfo
	printf("UE print rand a1: \n");
	BIO_dump_fp(stdout, (const char *)a1, sizeof(a1));
#endif

	unsigned char a2[16];
    memset(a2, 0xFF, sizeof(a2));
    RAND_bytes(a2, sizeof(a2));
#ifdef DebugAkmaInfo
    printf("UE print rand a2:\n");
	BIO_dump_fp(stdout, (const char *)a2, sizeof(a2));
#endif
	time_t t;

#ifdef DebugAkmaInfo
	printf("printf s_RSA_PK_AF: \n%s\n", PK_AF);
	// printf("printf s_RSA_PK_AAnF: \n%s\n", PK_AAnF);
#endif
	printf("UE Start\n");
	// Variable declaration
	struct sockaddr_in clAddr;
	struct sockaddr_in seafAddr;
	socklen_t addrlen = sizeof(seafAddr);
	int cl, recvlen;
	int  slen=sizeof(seafAddr);
	unsigned char buf[BUFSIZE];
	char *server ="127.0.0.1";

	//get_HomeNetworkPublicKey("127.0.0.1");

	// Set up client
	if ((cl = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("cannot create socket");
		exit(1);
	}
	memset((char *)&clAddr, 0, sizeof(clAddr));
	clAddr.sin_family = AF_INET;
	clAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	clAddr.sin_port = htons(CL_PORT);
	if(bind(cl, (struct sockaddr *)&clAddr, sizeof(clAddr))<0){
		perror("Bind failed");
		close(cl);
		return 0;
	}

	memset((char *) &seafAddr, 0, sizeof(seafAddr));
	seafAddr.sin_family = AF_INET;
	seafAddr.sin_port = htons(SV_PORT);
	if (inet_aton(server, &seafAddr.sin_addr)==0) {
		fprintf(stderr, "inet_aton() failed\n");
		exit(1);
	}
#ifdef measure
	printf("Tin: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif
	suci_t suci;
	uint8_t rand[16];
	uint8_t autn[16];
	get_SUCI(&suci);

#ifdef DebugAkmaInfo
	printf("UE print suci\n");
	printf("\t mcc_mnc:");
	for(int i=0; i< sizeof(suci.mcc_mnc);i++){
		printf("%02x", suci.mcc_mnc[i]);
	}
	printf("\n\t msin:");
	for(int i=0; i< sizeof(suci.msin);i++){
		printf("%02x", suci.msin[i]);
	}
	printf("\n\t ecc_pub_key:");
	for(int i=0; i< sizeof(suci.ecc_pub_key);i++){
		printf("%02x", suci.ecc_pub_key[i]);
	}
	printf("\n");
#endif

#ifdef testb
	printf("AuthReq\n");
#endif
	memset(buf, 0x00, sizeof(buf));
	int len_tmp = 0;
	strcpy(buf, "AuthReq");
	// strncat(buf, suci.mcc_mnc,sizeof(suci.mcc_mnc));
	// strncat(buf, suci.msin,sizeof(suci.msin));
	// strncat(buf, suci.ecc_pub_key,sizeof(suci.ecc_pub_key));
	len_tmp += strlen("AuthReq");
	memcpy(buf + len_tmp, suci.mcc_mnc,sizeof(suci.mcc_mnc));
	len_tmp += sizeof(suci.mcc_mnc);
	memcpy(buf + len_tmp, suci.msin,sizeof(suci.msin));
	len_tmp += sizeof(suci.msin);
	memcpy(buf + len_tmp, suci.ecc_pub_key,sizeof(suci.ecc_pub_key));
	len_tmp += sizeof(suci.ecc_pub_key);
#ifdef testb
	printf("\nUE print buf:");
	for(int i=0; i< 80;i++){
		printf("%02x", buf[i]);
	}
	puts("\n");
#endif
#ifdef showmethod
	printf("Send Authentication Request\n");
#endif
#ifdef measure
	printf("Tout: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif
	if(sendto(cl, buf, len_tmp, 0,(struct sockaddr *)&seafAddr, slen)==-1){
		perror("sendto");
		exit(1);
	}
	recvlen = recvfrom(cl, buf, BUFSIZE, 0, (struct sockaddr *)&seafAddr, &slen);
#ifdef showmethod
	printf("Receive Authentication Request\n");
#endif

	if(recvlen>=0){
		buf[recvlen]=0;
		//printf("MSG: ");
		for(int i=0;i<recvlen;i++){
			if(i<16){
			//	printf("%x",buf[i]);
				rand[i] = buf[i];
			} else
				if(i<32){
			//		printf("%x",buf[i]);
					autn[i-16]=buf[i];
			}
		}
		printf("\n");
	}
#ifdef measure
	printf("Tin: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif
#ifdef testb
	printf("Rand: ");
	for(int i=0;i<sizeof(rand);i++){
		printf("%x",rand[i]);
	}
	printf("\n");
	printf("Autn: ");
	for(int i=0;i<sizeof(autn);i++){
		printf("%x",autn[i]);
	}
	printf("\n");
#endif
	// Check if AUTN is accepted
	if(autnIsAccepted(autn, rand)!=1){
		return EXIT_FAILURE;
	}
	// Compute RES
	uint8_t res[8], ck[16], ik[16], res_star[32];
	computeRES(autn, rand, &res, &ck, &ik);

	// Compute RES_star
	calc_XRESstar(&res_star,sn_name_home,rand, res, ck, ik);
#ifdef testb
	printf("UE: RES_star\n");
	printf("\t res_star: ");
	for(int i = 0; i<32;i++){
		printf("%x",res_star[i]);
	}
	printf("\n");
#endif

	sprintf(buf, "AuthRes");
	for(int i=0;i<32;i++){
		buf[i+7]=res_star[i];
	}
	//strncat(buf, res_star, 32);
#ifdef testb
	printf("BUFFER: ");
	for(int i=0;i<39;i++){
		printf("%x",buf[i]);
	}
	printf("\n");
#endif
#ifdef measure
	printf("Tout: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif
#ifdef showmethod
	printf("Send Authentication Response\n");
#endif
		if(sendto(cl, buf, 39 , 0,(struct sockaddr *)&seafAddr, slen)==-1){
			perror("sendto");
			exit(1);
		}
	close(cl);

	printf("****************5G-AKA Exit*******\n\n\n\n");

	printf("****************5G-AKMA Begin ***************\n\n");


	// Variable declaration
	struct sockaddr_in af_clAddr;
	struct sockaddr_in af_seafAddr;
	socklen_t af_addrlen = sizeof(af_seafAddr);
	int af_cl, af_recvlen;
	int  af_slen=sizeof(af_seafAddr);
	unsigned char af_buf[BUFSIZE];
	unsigned char af_recv_buf[BUFSIZE];
	char *af_server ="127.0.0.1";

	// Set up client
	if ((af_cl = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("cannot create socket");
		exit(1);
	}
	memset((char *)&af_clAddr, 0, sizeof(af_clAddr));
	af_clAddr.sin_family = AF_INET;
	af_clAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	af_clAddr.sin_port = htons(CL_PORT);
	if(bind(af_cl, (struct sockaddr *)&af_clAddr, sizeof(af_clAddr))<0){
		perror("AF CL Bind failed");
		close(af_cl);
		return 0;
	}

	memset((char *) &af_seafAddr, 0, sizeof(af_seafAddr));
	af_seafAddr.sin_family = AF_INET;
	af_seafAddr.sin_port = htons(AF_PORT);
	if (inet_aton(af_server, &af_seafAddr.sin_addr)==0) {
		fprintf(stderr, "inet_aton() failed\n");
		exit(1);
	}


	memset(af_buf, 0x00, sizeof(af_buf));
	uint8_t k_ausf[32];

	derive_Kausf(sn_name, rand, k_ausf);

#ifdef DebugAkmaInfo
	printf("\nUE print k_ausf: ");
	for(int i=0;i<sizeof(k_ausf);i++){
		printf("%02x",k_ausf[i]);
	}
	printf("\n");

	printf("UE print g_supi\n");
	printf("\t mcc_mnc:");
	for(int i=0; i< sizeof(g_supi.mcc_mnc);i++){
		printf("%02x", g_supi.mcc_mnc[i]);
	}
	printf("\n\t msin:");
	for(int i=0; i< sizeof(g_supi.msin);i++){
		printf("%02x", g_supi.msin[i]);
	}
	printf("\n");
#endif

#ifdef measureAKMAfct
	uint64_t y0,z0;
	y0=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	//AKMA step 3a(UE calc) calc_Kakma_from_KAUSF(k_ausf,supi,k_akma)
	// calc_Kakma_from_KAUSF(k_ausf, &g_supi, &g_k_akma);

	//AKMA step 3b(UE calc) calc_AKID_from_KAUSF(k_ausf,supi,a_kid)
	// calc_AKID_from_KAUSF(k_ausf, &g_supi, &g_a_kid);


	size_t akma_pair_size = 1;
	akma_pair_t akma_pair[akma_pair_size];

	unsigned char currentDate[9];
	getCurrentDate(currentDate);

	for (int i = 0; i < akma_pair_size; i++)
	{
		// AKMA step 3a(UE calc)
		// generate k_akma
		calc_Kakma_from_KAUSF_2(k_ausf, &g_supi, i, currentDate, &(akma_pair[i].k_akma));

		// AKMA step 3b(UE calc)
		// generate a_kid
		calc_AKID_from_KAUSF_2(k_ausf, &g_supi, i, currentDate, &(akma_pair[i].a_kid));
	}


	int rand_i = getRand(akma_pair_size);
	g_k_akma = akma_pair[rand_i].k_akma;
	g_a_kid = akma_pair[rand_i].a_kid;

#ifdef measureAKMAfct
	z0=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	printf("UE step 3a, 3b Duration %lu ns\n",z0-y0);
#endif

	//step 6 Derive AF key from K-AKMA(change step 10 to step 6.)
	memset(g_af_id.fqdn, 0xFF, sizeof(g_af_id.fqdn));
    memset(g_af_id.uaid, 0xFF, sizeof(g_af_id.uaid));
	calc_KAF_from_KAKMA(&g_k_akma, &g_af_id, &g_k_af);

#ifdef showmethod
	printf("********UE: sleep 1 second********\n");
#endif
	// wait until SEAF 5G-AKA complete, and 5G-AKMA step 1 to step 5 complete.
	usleep(1000 * 1000);

	//step 6
#ifdef measureAKMAfct
	uint64_t y1,z1;
	y1=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	char *ASERequest = "ASERequest"; //Application Session Establishment Requsest(A-KID)
	/*
	buf = "ASERequest" + g_a_kid + 
			SEnc_CT_UE_AF_len(4 bytes) + Enc_CT_UE_AF +
			SEnc_CT_UE_AAnF_len(4 bytes) + SEnc_CT_UE_AAnF + CT_UE_AAnF_TAG(2 bytes)
	*/
	int af_len_tmp = 0;
	memcpy(af_buf + af_len_tmp, ASERequest, strlen(ASERequest));
	af_len_tmp += strlen(ASERequest);
	int offset = 0;

	offset = ParseAKID2Buf(&g_a_kid, af_buf + af_len_tmp, sizeof(af_buf) - af_len_tmp);
	af_len_tmp += offset;

	//add CT_AF, CT_AANF
#ifdef measureAKMAfct
	z1=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("A: %lu \n",y1);
	// printf("B: %lu \n",z1);
	printf("UE step 6 Duration %lu ns\n",z1-y1);
#endif

#ifdef measureAKMAfct
	uint64_t y10,z10;
	y10=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	// unsigned char *Enc_CT_UE_AF;
	size_t Enc_CT_UE_AF_len = 0;
	// Enc_CT_UE_AF = getCT_UE_AF(a1, sizeof(a1), &Enc_CT_UE_AF_len);
	size_t CT_UE_AF_len = sizeof(U) + sizeof(a1);
	unsigned char CT_UE_AF[CT_UE_AF_len];
	memset(CT_UE_AF, 0X00, sizeof(CT_UE_AF));
	memcpy(CT_UE_AF, U, sizeof(U));
	memcpy(CT_UE_AF + sizeof(U), a1, sizeof(a1));
	unsigned char Enc_CT_UE_AF[BUFSIZ];
	memset(Enc_CT_UE_AF, 0x00, sizeof(Enc_CT_UE_AF));
	Enc_CT_UE_AF_len = encrypt(CT_UE_AF, CT_UE_AF_len, 
		UE_AF_ECIES_Shared_Secret_Key, NULL, Enc_CT_UE_AF);
#ifdef DebugAkmaInfo
	printf("UE get encrypted CT_UE_AF (len:%d) is:\n", Enc_CT_UE_AF_len);
	BIO_dump_fp(stdout, (const char *)Enc_CT_UE_AF, Enc_CT_UE_AF_len);
#endif

	unsigned char SEnc_CT_UE_AAnF[16];
    memset(SEnc_CT_UE_AAnF, 0xFF, sizeof(SEnc_CT_UE_AAnF));
	unsigned char CT_UE_AAnF_TAG[TAG_SIZE];

    // int SEnc_CT_UE_AAnF_Len = encrypt(a2, sizeof(a2), g_k_af.k_af, NULL, SEnc_CT_UE_AAnF);
	int SEnc_CT_UE_AAnF_Len = gcm_encrypt(a2, sizeof(a2), g_k_akma.k_akma, iv, IV_LEN, 
				SEnc_CT_UE_AAnF, CT_UE_AAnF_TAG, TAG_SIZE);

#ifdef DebugAkmaInfo
    printf("encrypted SEnc_CT_UE_AAnF (len:%d) is:\n", SEnc_CT_UE_AAnF_Len);
	BIO_dump_fp(stdout, (const char *)SEnc_CT_UE_AAnF, SEnc_CT_UE_AAnF_Len);
	printf("CT_UE_AAnF_TAG (len:%d) is:\n", TAG_SIZE);
	BIO_dump_fp(stdout, (const char *)CT_UE_AAnF_TAG, TAG_SIZE);
#endif

	sprintf(af_buf + af_len_tmp, "%04d", Enc_CT_UE_AF_len);
	af_len_tmp += 4;

	memcpy(af_buf + af_len_tmp, Enc_CT_UE_AF, Enc_CT_UE_AF_len);
	af_len_tmp += Enc_CT_UE_AF_len;

	sprintf(af_buf + af_len_tmp, "%04d", SEnc_CT_UE_AAnF_Len);
	af_len_tmp += 4;

	memcpy(af_buf + af_len_tmp, SEnc_CT_UE_AAnF, SEnc_CT_UE_AAnF_Len);
	af_len_tmp += SEnc_CT_UE_AAnF_Len;

	memcpy(af_buf + af_len_tmp, CT_UE_AAnF_TAG, TAG_SIZE);
	af_len_tmp += TAG_SIZE;
	
#ifdef measureAKMAfct
	z10=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("A: %lu \n",y1);
	// printf("B: %lu \n",z1);
	printf("UE step 6 akma+ add Duration %lu ns\n",z10-y10);
#endif

	// printf("AKMA step 6 (UE-->AF) Application_Session_Establishment_Request_AF(A-KID) send\n");
	Application_Session_Establishment_Request_UE(&g_a_kid);


#ifdef CommCosts 
	printf("\nAKMA step 6 (UE-->AF) UE send message to AF(%d bytes)\n", af_len_tmp);
#ifdef DebugAkmaInfo
	for(int i=0; i< af_len_tmp;i++){
		printf("%02x", af_buf[i]);
	}
	printf("\n");
#endif

#endif
	if(sendto(af_cl, af_buf, af_len_tmp, 0,(struct sockaddr *)&af_seafAddr, af_slen)==-1){
		perror("sendto");
		exit(1);
	}

	af_recvlen = recvfrom(af_cl, af_recv_buf, BUFSIZE, 0, (struct sockaddr *)&af_seafAddr, &af_slen);
	Application_Session_Establishment_Response_UE();
#ifdef CommCosts 
	printf("\nAKMA step 14 (AF-->UE) UE receive message from AF(%d bytes)\n", af_recvlen);
#ifdef DebugAkmaInfo
	for(int i=0; i< af_recvlen;i++){
		printf("%02x", af_recv_buf[i]);
	}
	printf("\n");
#endif
#endif

#ifdef measureAKMAfct
	uint64_t y2,z2;
	y2=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	// af_recv_buf = "ASEResponse" + SEnc_CT_AAnF_UE_Len(4 bytes) + SEnc_CT_AAnF_UE + CT_AAnF_UE_TAG(2 bytes) +
    // 								 Res_AF_len(4 bytes) + Res_AF + Res_AF_Sign_len(4 bytes) + Res_AF_Sign
	
	// unsigned char str_Res_AAnF_len[5];
	// unsigned int Res_AAnF_len;
	// unsigned char Res_AAnF[BUFSIZ];
	// unsigned char Res_AAnF_Sign[BUFSIZ];
	unsigned char a2plus1[8];
	unsigned char CT_AAnF_UE[BUFSIZ];
	unsigned char CT_AAnF_UE_TAG[TAG_SIZE];
	unsigned char SEnc_CT_AAnF_UE[BUFSIZ];
	unsigned int SEnc_CT_AAnF_UE_Len;
	unsigned char Str_SEnc_CT_AAnF_UE_Len[5];

	unsigned char str_Res_AF_len[5]; 
	unsigned int Res_AF_len;
	unsigned char Res_AF[BUFSIZ];
	unsigned char str_Res_AF_Sign_len[5]; 
	unsigned int Res_AF_Sign_len;
	unsigned char Res_AF_Sign[BUFSIZ];
	unsigned char V[65];
	offset = 11;

	// memset(str_Res_AAnF_len, 0x00, sizeof(str_Res_AAnF_len));
	// memcpy(str_Res_AAnF_len, af_recv_buf+ offset, 4);
	// offset += 4;

	// Res_AAnF_len = atoi(str_Res_AAnF_len);
	// memcpy(Res_AAnF, af_recv_buf+ offset, Res_AAnF_len);
	// offset += Res_AAnF_len;

	// memcpy(Res_AAnF_Sign, af_recv_buf+ offset, 128);
	// offset += 128;

	memset(Str_SEnc_CT_AAnF_UE_Len, 0x00, sizeof(Str_SEnc_CT_AAnF_UE_Len));
	memcpy(Str_SEnc_CT_AAnF_UE_Len, af_recv_buf + offset, 4);
	SEnc_CT_AAnF_UE_Len = atoi(Str_SEnc_CT_AAnF_UE_Len);
	offset += 4;
	memcpy(SEnc_CT_AAnF_UE, af_recv_buf + offset, SEnc_CT_AAnF_UE_Len);
	offset += SEnc_CT_AAnF_UE_Len;
	memcpy(CT_AAnF_UE_TAG, af_recv_buf + offset, TAG_SIZE);
	offset += TAG_SIZE;

#ifdef DebugAkmaInfo
	printf("encrypt SEnc_CT_AAnF_UE (len:%d) is:\n", SEnc_CT_AAnF_UE_Len);
	BIO_dump_fp(stdout, (const char *)SEnc_CT_AAnF_UE, SEnc_CT_AAnF_UE_Len);
	printf("CT_AAnF_UE_TAG (len:%d) is:\n", TAG_SIZE);
	BIO_dump_fp(stdout, (const char *)CT_AAnF_UE_TAG, TAG_SIZE);
#endif

	int CT_AAnF_UE_Len = gcm_encrypt(SEnc_CT_AAnF_UE, SEnc_CT_AAnF_UE_Len, g_k_akma.k_akma, iv, IV_LEN, 
				CT_AAnF_UE, CT_AAnF_UE_TAG, TAG_SIZE);

#ifdef DebugAkmaInfo
	printf("decrypt CT_AAnF_UE i.e. a2 + 1 (len:%d) is:\n", CT_AAnF_UE_Len);
	BIO_dump_fp(stdout, (const char *)CT_AAnF_UE, CT_AAnF_UE_Len);
	printf("a2  (len:%d) is:\n", sizeof(a2));
	BIO_dump_fp(stdout, (const char *)a2, sizeof(a2));
#endif

	memset(str_Res_AF_len, 0x00, sizeof(str_Res_AF_len));
	memcpy(str_Res_AF_len, af_recv_buf+ offset, 4);
	offset += 4;

	Res_AF_len = atoi(str_Res_AF_len);
	memcpy(Res_AF, af_recv_buf+ offset, Res_AF_len);
	offset += Res_AF_len;

	memset(str_Res_AF_Sign_len, 0x00, sizeof(str_Res_AF_Sign_len));
	memcpy(str_Res_AF_Sign_len, af_recv_buf+ offset, 4);
	offset += 4;

	Res_AF_Sign_len = atoi(str_Res_AF_Sign_len);
	memcpy(Res_AF_Sign, af_recv_buf+ offset, Res_AF_Sign_len);
	offset += Res_AF_Sign_len;
#ifdef DebugAkmaInfo
	printf("\nverifySign print PK_AF: \n %s \n", PK_AF);
	printf("\nverifySign print Res_AF: %d \n", Res_AF_len);
	BIO_dump_fp(stdout, (const char *)Res_AF, Res_AF_len);
	printf("\nverifySign print Res_AF_Sign: %d \n", Res_AF_Sign_len);
	BIO_dump_fp(stdout, (const char *)Res_AF_Sign, Res_AF_Sign_len);
#endif
	int verify_result_AF = verifySign(PK_AF, Res_AF_Sign, Res_AF_Sign_len, Res_AF, Res_AF_len);

	memcpy(V, Res_AF, sizeof(V));

	unsigned char *Ks_u=NULL;
	size_t Ks_u_Len = 0;

	Ks_u = getSharedKey(p_u, V, &Ks_u_Len);
#ifdef DebugAkmaInfo
	printf("Ks_u (len:%d) is:\n", Ks_u_Len);
	BIO_dump_fp(stdout, (const char *)Ks_u, Ks_u_Len);
#endif


// #ifdef DebugAkmaInfo
// 	printf("\nverifySign print PK_AAnF: \n %s \n", PK_AAnF);
// 	printf("\nverifySign print Res_AAnF: %d \n", Res_AAnF_len);
// 	BIO_dump_fp(stdout, (const char *)Res_AAnF, Res_AAnF_len);
// 	printf("\nverifySign print Res_AAnF_Sign: %d \n", Res_AAnF_len);
// 	BIO_dump_fp(stdout, (const char *)Res_AAnF_Sign, 128);
// #endif

// 	int verify_result_AAnF = verifySign(PK_AAnF, Res_AAnF_Sign, 128, Res_AAnF, Res_AAnF_len);


	
// #ifdef DebugAkmaInfo
// 	printf("\nverify_result_AF = %d\t verify_result_AAnF =%d\n", verify_result_AF, verify_result_AAnF);
// #endif

	unsigned char K_AF_prime[128];
	size_t K_AF_prime_Len = 128;
	unsigned char K_AF_Ks_u[BUFSIZ];
	offset = 0;
	memcpy(K_AF_Ks_u + offset, g_k_af.k_af, sizeof(g_k_af.k_af));
	offset += sizeof(g_k_af.k_af);

	memcpy(K_AF_Ks_u + offset, Ks_u, Ks_u_Len);
	offset += Ks_u_Len;

	kdf(K_AF_Ks_u, offset, &K_AF_prime_Len, NULL, 0, K_AF_prime);
#ifdef DebugAkmaInfo
	printf("K_AF_prime (len:%d) is:\n", K_AF_prime_Len);
	BIO_dump_fp(stdout, (const char *)K_AF_prime, K_AF_prime_Len);
#endif

#ifdef measureAKMAfct
	z2=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("A: %lu \n",y2);
	// printf("B: %lu \n",z2);
	printf("UE step 14 akma+ add Duration %lu ns\n",z2-y2);
#endif

// #ifdef DebugAkmaInfo
// 	printf("Receive Application_Session_Establishment_Response(AF->UE), msg(%d): \n", af_recvlen);
//     if(af_recvlen>=0){
// 		for(int i=0;i<af_recvlen;i++){
// 			printf("%02x", af_recv_buf[i]);
// 		}
// 		printf("\n");
// 	}
// #endif

	// calc_KafPrime_from_KAF(&g_k_af, s_Ksu, &g_k_af_prime);

	close(af_cl);

	if(s_Ksu != NULL) {
		free(s_Ksu);
	}
	if(AF_ECDSA_Pubkey != NULL)
		free(AF_ECDSA_Pubkey);
	if(AF_ECIES_Pubkey != NULL)
		free(AF_ECIES_Pubkey);

	if(UE_ECIES_Pubkey != NULL)
		free(UE_ECIES_Pubkey);
	if(s_UE_ECIES_pkey != NULL)
		EVP_PKEY_free(s_UE_ECIES_pkey);
	printf("UE Exit\n");
	return EXIT_SUCCESS;
}

/*
use rsa verify, pub_key is rsa public key
unsigned char * pub_key: input, rsa public key
unsigned char *signed_value : input
size_t signed_value_len: input
unsigned char *sign_data: input
size_t sign_data_len: input

return:
	0 -- verify fail
	1 -- verify success
*/
int verifySign(unsigned char * pub_key, unsigned char *signed_value, size_t signed_value_len,
	unsigned char *sign_data, size_t sign_data_len){
	
#ifdef measureAKMAfct2
	uint64_t y10,z10;
	y10=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	// BIO *UE_bio = NULL;
    // UE_bio = BIO_new(BIO_s_mem());
    // BIO_puts(UE_bio, pub_key);
    // EVP_PKEY * veriry_pkey;
    // if (NULL == (veriry_pkey = PEM_read_bio_PUBKEY(UE_bio, NULL, NULL, NULL) ))
    // {
	// 	BIO_free(UE_bio);
    //     handleErrors();
    // }

    EVP_MD_CTX *verify_mdctx = EVP_MD_CTX_new();

	// initialize ctx
    EVP_MD_CTX_init(verify_mdctx);
	// verity initialize,  md must be the same as sign
    if(!EVP_VerifyInit_ex(verify_mdctx, EVP_sha256(), NULL))
    {  
		handleErrors();
		// BIO_free(UE_bio);
		EVP_MD_CTX_free(verify_mdctx);
        return 0;  
    }  
	// add verify data
    if(!EVP_VerifyUpdate(verify_mdctx, sign_data, sign_data_len))
    {  
        handleErrors();
		// BIO_free(UE_bio);
		EVP_MD_CTX_free(verify_mdctx);
        return 0;  
    }     

	// verify s_AF_ECDSA_pkey
    // if(!EVP_VerifyFinal(verify_mdctx,signed_value,signed_value_len,veriry_pkey))
	if(!EVP_VerifyFinal(verify_mdctx,signed_value,signed_value_len,s_AF_ECDSA_pkey))
    {  
        handleErrors();
		// BIO_free(UE_bio);
		EVP_MD_CTX_free(verify_mdctx);
        return 0;  
    }  
    else  
    { 
#ifdef DebugAkmaInfo
        printf("verify sucessfully\n");  
#endif
#ifdef measureAKMAfct2
	z10=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	printf("UE Verify step 14 verifySign Duration %lu ns\n",z10-y10);
#endif
		return 1;
    }  
    // BIO_free(UE_bio);
	EVP_MD_CTX_free(verify_mdctx);
	return 1;

}

void getCurrentDate(unsigned *date)
{
	struct timeval tv;
	struct tm *t;

	gettimeofday(&tv, NULL);
	t = localtime(&tv.tv_sec);
	sprintf(date, "%04d%02d%02d", 1900 + t->tm_year, 1 + t->tm_mon, t->tm_mday);
}

// AKMA
/*
k_ausf:input
supi:input
k_akma:output
*/
static void calc_Kakma_from_KAUSF(k_ausf_t *k_ausf, supi_t *supi, k_akma_t *k_akma){
#ifdef showAKMAmethod
    printf("AKMA step 3a(UE calc) calc_Kakma_from_KAUSF(k_ausf,supi,k_akma) begin \n");
#endif

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	int SIZE_K_AUSF = 32;
	int SIZE_K_AKMA = 4;
	uint8_t fc = 0x80;
	char pn[SIZE_K_AKMA+sizeof(supi_t)];
	memcpy(pn, "AKMA", SIZE_K_AKMA);
	uint16_t ln[2];
	ln[0] = SIZE_K_AKMA;
	memcpy(pn+SIZE_K_AKMA, supi->mcc_mnc, sizeof(supi->mcc_mnc));
	memcpy(pn+SIZE_K_AKMA+sizeof(supi->mcc_mnc), supi->msin, sizeof(supi->msin));
	ln[1] = sizeof(supi_t);

#ifdef DebugAkmaInfo
	printf("\n");
	printf("\t supi: ");
	for(int i=0; i<8; i++){
		if(i<3){
			printf("%02x", supi->mcc_mnc[i]);
		} else {
			printf("%02x", supi->msin[i-3]);
		}
	}
	printf("\n");

	printf("UE befor AKMA print k_ausf(%d): ", SIZE_K_AUSF);
	for(int i=0;i<sizeof(k_ausf_t);i++){
		printf("%02x",k_ausf->k_ausf[i]);
	}
	printf("\n");
	printf("UE befor AKMA print fc: ");
	for(int i=0;i<sizeof(fc);i++){
		printf("%02x",fc);
	}
	printf("\n");
	printf("UE befor AKMA print pn: ");
	for(int i=0;i<sizeof(pn);i++){
		printf("%02x",pn[i]);
	}
	printf("\n");
	printf("UE befor AKMA print ln: ");
	for(int i=0;i<2;i++){
		printf("%02x",ln[i]);
	}
	printf("\n");
#endif
	// uint8_t output[32];
	// memset(output, 0xff, sizeof(output));
	// printf("\n");
	// printf("UE before genericKeyDerivation print output: ");
	// for(int i=0; i<32; i++){
	// 	printf("%02x",output[i]);
	// }
	// printf("\n");

	genericKeyDerivation(k_ausf->k_ausf,SIZE_K_AUSF,fc,(uint8_t*)pn,ln,2,k_akma->k_akma);

#ifdef DebugAkmaInfo
	printf("\n");
	printf("UE calc_Kakma_from_KAUSF after genericKeyDerivation print k_akma->k_akma: ");
	for(int i=0; i<32; i++){
		printf("%02x",k_akma->k_akma[i]);
	}
	printf("\n");
#endif

#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("UE step 3a Duration %lu ns\n",z-y);
#endif
}

// AKMA
/*
k_ausf:input
supi:input
counter:input
date:input
k_akma:output
*/
static void calc_Kakma_from_KAUSF_2(k_ausf_t *k_ausf, supi_t *supi,
									   int counter, unsigned char *date, k_akma_t *k_akma)
{
#ifdef showAKMAmethod
	printf("AKMA step 3a(UE calc) calc_Kakma_from_KAUSF(k_ausf,supi,k_akma) begin \n");
#endif
#ifdef measureAKMAfct2
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	int SIZE_K_AUSF = 32;
	int SIZE_K_AKMA = 4;
	int COUNTER_LEN = 3;
	int DATE_LEN = 8;
	uint8_t fc = 0x80;
	// length of counter = 3 0~99
	// length of date = 8 yyyyddmm
	char pn[SIZE_K_AKMA + sizeof(supi_t) + COUNTER_LEN + DATE_LEN];
	int ln_len = 4;
	uint16_t ln[ln_len];
	int offset = 0;

	memcpy(pn + offset, "AKMA", SIZE_K_AKMA);
	offset += SIZE_K_AKMA;
	ln[0] = SIZE_K_AKMA;

	memcpy(pn + offset, supi->mcc_mnc, sizeof(supi->mcc_mnc));
	offset += sizeof(supi->mcc_mnc);
	memcpy(pn + offset, supi->msin, sizeof(supi->msin));
	offset += sizeof(supi->msin);
	ln[1] = sizeof(supi_t);

	unsigned char str_counter[4];
	sprintf(str_counter, "%03d", counter);
	memcpy(pn + offset, str_counter, COUNTER_LEN);
	offset += COUNTER_LEN;
	ln[2] = COUNTER_LEN;

	memcpy(pn + offset, date, DATE_LEN);
	offset += DATE_LEN;
	ln[3] = DATE_LEN;

	genericKeyDerivation(k_ausf->k_ausf, SIZE_K_AUSF, fc, (uint8_t *)pn, ln, ln_len, k_akma->k_akma);

#ifdef measureAKMAfct2
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	printf("UE step 3a Duration %lu ns\n",z-y);
#endif
#ifdef DebugAkmaInfo
	printf("\n");
	printf("UE calc_Kakma_from_KAUSF after genericKeyDerivation \n\t counter = %d, date = %s \n, \t print k_akma->k_akma: ", counter, date);
	for (int i = 0; i < 32; i++)
	{
		printf("%02x", k_akma->k_akma[i]);
	}
	printf("\n");
#endif
}


/*
k_ausf:input
supi:input
a_kid:output
*/
static void calc_AKID_from_KAUSF(k_ausf_t *k_ausf, supi_t *supi, a_kid_t *a_kid){
#ifdef showAKMAmethod
    printf("AKMA step 3b(UE calc) calc_AKID_from_KAUSF(k_ausf,supi,a_kid) begin \n");
#endif

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	int SIZE_K_AUSF = 32;
	int SIZE_K_ATID = 5;
	uint8_t fc = 0x81;
	char pn[SIZE_K_ATID+sizeof(supi_t)];
	memcpy(pn, "A-TID", SIZE_K_ATID);
	uint16_t ln[2];
	ln[0] = SIZE_K_ATID;
	memcpy(pn+SIZE_K_ATID, supi->mcc_mnc, sizeof(supi->mcc_mnc));
	memcpy(pn+SIZE_K_ATID+sizeof(supi->mcc_mnc), supi->msin, sizeof(supi->msin));
	ln[1] = sizeof(supi_t);

#ifdef DebugAkmaInfo
	printf("\n");
	printf("\t supi: ");
	for(int i=0; i<8; i++){
		if(i<3){
			printf("%x", supi->mcc_mnc[i]);
		} else {
			printf("%x", supi->msin[i-3]);
		}
	}
	printf("\n");
#endif

	uint8_t a_tid[32];

	genericKeyDerivation(k_ausf,SIZE_K_AUSF,fc,(uint8_t*)pn,ln,2,a_tid);

	for(int i=0;i<4;i++) {
		(g_rid.rid)[i] =i+1;
	}

	memcpy((a_kid->username).a_tid, a_tid, sizeof(a_tid));
	memcpy(&(a_kid->username).rid, &g_rid, sizeof(g_rid));

	memcpy(a_kid->at, "@", 1);
	memset(a_kid->realm, 0xFF, sizeof(a_kid->realm));

#ifdef DebugAkmaInfo
	printf("\n");
	printf("UE calc_AKID_from_KAUSF after genericKeyDerivation print a_kid: \n");
	printf("\t a_kid: \n");
	printf("\t\t username: \n");
	printf("\t\t\t rid: ");
	for(int i=0; i<sizeof((a_kid->username).rid); i++){
		printf("%02x",(a_kid->username).rid.rid[i]);
	}
	printf("\n");
	printf("\t\t\t a_tid: ");
	for(int i=0; i<32; i++){
		printf("%02x",(a_kid->username).a_tid[i]);
	}
	printf("\n");
	printf("\t\t at: %c\n", (a_kid->at)[0]);

	printf("\t\t realm: ");
	for(int i=0; i<sizeof(a_kid->realm); i++){
		printf("%02x",(a_kid->realm)[i]);
	}
	printf("\n");
#endif

#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("UE step 3b Duration %lu ns\n",z-y);
#endif
}

/*
k_ausf:input
supi:input
counter:input
date:input
a_kid:output
*/
static void calc_AKID_from_KAUSF_2(k_ausf_t *k_ausf, supi_t *supi,
									  int counter, unsigned char *date, a_kid_t *a_kid)
{
#ifdef showAKMAmethod
	printf("AKMA step 3b(UE calc) calc_AKID_from_KAUSF(k_ausf,supi,a_kid) begin \n");
#endif
#ifdef measureAKMAfct2
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	int SIZE_K_AUSF = 32;
	int SIZE_K_ATID = 5;
	int COUNTER_LEN = 3;
	int DATE_LEN = 8;
	uint8_t fc = 0x81;
	// length of counter = 3 0~99
	// length of date = 8 yyyyddmm
	char pn[SIZE_K_ATID + sizeof(supi_t) + COUNTER_LEN + DATE_LEN];
	int ln_len = 4;
	uint16_t ln[ln_len];

	int offset = 0;
	memcpy(pn + offset, "A-TID", SIZE_K_ATID);
	offset += SIZE_K_ATID;
	ln[0] = SIZE_K_ATID;

	memcpy(pn + offset, supi->mcc_mnc, sizeof(supi->mcc_mnc));
	offset += sizeof(supi->mcc_mnc);
	memcpy(pn + offset, supi->msin, sizeof(supi->msin));
	offset += sizeof(supi->msin);
	ln[1] = sizeof(supi_t);

	unsigned char str_counter[4];
	sprintf(str_counter, "%03d", counter);
	memcpy(pn + offset, str_counter, COUNTER_LEN);
	offset += COUNTER_LEN;
	ln[2] = COUNTER_LEN;

	memcpy(pn + offset, date, DATE_LEN);
	offset += DATE_LEN;
	ln[3] = DATE_LEN;

	uint8_t a_tid[32];

	genericKeyDerivation(k_ausf, SIZE_K_AUSF, fc, (uint8_t *)pn, ln, ln_len, a_tid);

	for (int i = 0; i < 4; i++)
	{
		(g_rid.rid)[i] = i + 1;
	}

	memcpy((a_kid->username).a_tid, a_tid, sizeof(a_tid));
	memcpy(&(a_kid->username).rid, &g_rid, sizeof(g_rid));

	memcpy(a_kid->at, "@", 1);
	memset(a_kid->realm, 0xFF, sizeof(a_kid->realm));
#ifdef measureAKMAfct2
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	printf("UE step 3b Duration %lu ns\n",z-y);
#endif
#ifdef DebugAkmaInfo
	printf("\n");
	printf("UE calc_AKID_from_KAUSF after genericKeyDerivation print a_kid: \n");
	printf("\t a_kid: \n");
	printf("\t\t username: \n");
	printf("\t\t\t rid: ");
	for (int i = 0; i < sizeof((a_kid->username).rid); i++)
	{
		printf("%02x", (a_kid->username).rid.rid[i]);
	}
	printf("\n");
	printf("\t\t\t a_tid: ");
	for (int i = 0; i < 32; i++)
	{
		printf("%02x", (a_kid->username).a_tid[i]);
	}
	printf("\n");
	printf("\t\t at: %c\n", (a_kid->at)[0]);

	printf("\t\t realm: ");
	for (int i = 0; i < sizeof(a_kid->realm); i++)
	{
		printf("%02x", (a_kid->realm)[i]);
	}
	printf("\n");
#endif
}

// k_akma: input
// af_id: input
// k_af: output
static void calc_KAF_from_KAKMA(k_akma_t *k_akma, af_id_t *af_id, k_af_t *k_af){
#ifdef showAKMAmethod
    printf("AKMA step 6 (UE calc) calc_KAF_from_KAKMA(k_akma_t,af_id_t,k_af_t) begin \n");
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
	printf("UE calc_KAF_from_KAKMA print k_af->k_af: ");
	for(int i=0;i<sizeof(k_af->k_af);i++){
		printf("%02x",(k_af->k_af)[i]);
	}
	printf("\n");
#endif

#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("UE step 6 calc_KAF_from_KAKMA Duration %lu ns\n",z-y);
#endif

}

/*
input:
k_af[32]
k_s[48]

output:
k_af_prime[32]
*/
void calc_KafPrime_from_KAF(k_af_t *k_af, uint8_t *k_s, k_af_prime_t *k_af_prime)
{

    int SIZE_K_S = 48;
    uint8_t fc = 0xF0;
    char pn[SIZE_K_S];
    uint16_t ln[1];
    memcpy(pn, k_s, SIZE_K_S);
    ln[1] = SIZE_K_S;

    
#ifdef measureAKMAfct
    uint64_t a, b;
    a = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
    genericKeyDerivation(k_af->k_af, 32, fc, (uint8_t *)pn, ln, 1, k_af_prime->k_af_prime);
#ifdef measureAKMAfct
    b = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
    printf("Derive k_af_prime Duration %lu ns\n", b - a);
#endif
#ifdef DebugAkmaInfo
    printf("print k_af_prime->k_af_prime: \n");
    for (int i = 0; i < sizeof(k_af_prime->k_af_prime); i++)
    {
        printf("%02x", (k_af_prime->k_af_prime)[i]);
    }
    printf(" \n");
#endif
}

void Application_Session_Establishment_Request_UE(a_kid_t *a_kid)
{
#ifdef showAKMAmethod
    printf("AKMA step 6 (UE-->AF) Application_Session_Establishment_Request_UE(A-KID) \n");
#endif
}

void Application_Session_Establishment_Response_UE()
{
#ifdef showAKMAmethod
    printf("AKMA step 14 (AF-->UE) Application_Session_Establishment_Response_UE receive\n");
#endif
}