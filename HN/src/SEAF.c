/*
 ============================================================================
 Name        : SEAF.c
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "identifier.h"
#include "av_types.h"
#include "AUSF.h"
#include "sidf.h"
#include "defs.h"
#include "AAnF.h"
#include <time.h>
#include "genericFunctions.h"

#define SV_PORT 50001

#define BUFSIZE 2048

sn_name_t sn_name = "5G:NTNUnet";
static se_av_t g_se_av;
static supi_t g_supi;
static suci_t g_suci;
static uint8_t kseaf[32];
static int ebene = 0;

// extern size_t s_RSA_pubkey_len;  
// extern char *s_RSA_PK_AAnF;
extern unsigned char homeNetworkPublicKey[65];

size_t PK_AAnF_len; 
char *PK_AAnF;
size_t SK_AAnF_len;                // Length of private key
char *SK_AAnF;       // RSA Private key


static void calc_HRESstar(uint8_t hres_star[16], uint8_t res_star[32], uint8_t rand[16])
{
#ifdef showmethod
	printm(ebene, "SEAF: computeHRES\n");
#endif
#ifdef measurefct
	uint64_t y, z;
	y = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef testb
	printf("\t res_star: ");
	for (int i = 0; i < 32; i++)
	{
		printf("%x", res_star[i]);
	}
	printf("\n");
	printf("\t rand: ");
	for (int i = 0; i < 16; i++)
	{
		printf("%x", rand[i]);
	}
	printf("\n");
#endif
	// HRES* and HXRES* derivation function (TS33.501, Annex A.5)
	int n = 2;

	int rand_size = 16, xres_star_size = 32;
	uint8_t fc = NULL;
	unsigned char s[rand_size + xres_star_size];
	uint16_t ln[n];
	for (int i = 0; i < rand_size; i++)
	{
		s[i] = (unsigned char)rand[i];
	}
	for (int i = 0; i < xres_star_size; i++)
	{
		s[rand_size + i] = (unsigned char)res_star[i];
	}

	const unsigned char s_tmp[sizeof(s)], md[32];
	memcpy(s_tmp, s, sizeof(s));
	// SHA256
	SHA256(s, sizeof(s), md);
	for (int i = 0; i < sizeof(md); i++)
	{
		hres_star[i] = (uint8_t)md[i];
	}

#ifdef measurefct
	z = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("Nausf_UEAuthenticationRequest %lu \n", y);
	printf("B: %lu \n", z);
	printf("calc_HRESstar Duration %lu ns\n", z - y);
#endif
	return;
}

static void derive_Kamf(uint8_t *k_amf, uint8_t *k_seaf, supi_t supi)
{
#ifdef showmethod
	printm(ebene, "SEAF: derive_Kamf\n");
#endif
#ifdef measurefct
	uint64_t y, z;
	y = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	// K_amf derivation function (TS33.501, Annex A.7)
	int n = 2;

	uint8_t fc = 0x6d;
	const char *pn[n];
	uint16_t ln[n];
	// char *supi_tmp;
	// strcpy(supi_tmp, supi.mcc_mnc);
	// strncat(supi_tmp, supi.msin, 5);
	char supi_tmp[sizeof(supi)];
	memcpy(supi_tmp, supi.mcc_mnc, sizeof(supi.mcc_mnc));
	memcpy(supi_tmp + sizeof(supi.mcc_mnc), supi.msin, sizeof(supi.msin));
	pn[0] = supi_tmp;
	ln[0] = 8;
	pn[1] = 0x0000; // ABBA parameter, see TS33.501, Annex A.7.1
	ln[1] = sizeof(0x0000);

	genericKeyDerivation(k_seaf, sizeof(k_seaf), fc, pn, ln, n, k_amf);

#ifdef measurefct
	z = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n", y);
	printf("B: %lu \n", z);
	printf("derive_Kamf Duration %lu ns\n", z - y);
#endif
	return;
}

static void Nseaf_UEAuthenticationRequest(se_av_t *se_av, unsigned char *msg)
{
#ifdef showmethod
	printm(ebene, "SEAF: Nseaf_UEAuthenticationRequest Begin\n");
#endif
#ifdef measure
	printf("Tin: %lu \n", clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif
#ifdef measurefct
	uint64_t y, z;
	y = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	// Extract SUCI/5G-GUTI
	// suci_t suci;

	int actualSize = 7, start = 7;
	actualSize += sizeof(g_suci.mcc_mnc);
#ifdef DebugAkmaInfo
	printf("SEAF print request msg:");
	for (int i = 0; i < start + sizeof(g_suci); i++)
	{
		printf("%02x", msg[i]);
	}
	printf("\n");
#endif
	// Get MCC & MNC
	// puts("\nmcc_mnc: ");
	for (int i = start; i < actualSize; i++)
	{
		//	printf("%x", msg[i]);
		g_suci.mcc_mnc[i - start] = (uint8_t)msg[i];
	}

	// Get MSIN
	start = actualSize;
	actualSize += sizeof(g_suci.msin);
	// puts("\nmsin:");
	for (int i = start; i < actualSize; i++)
	{
		//	printf("%x", msg[i]);
		g_suci.msin[i - start] = (uint8_t)msg[i];
	}

	// Get ECC Public Key
	start = actualSize;
	actualSize += sizeof(g_suci.ecc_pub_key);
	// puts("\neccpubkey:");
	for (int i = start; i < actualSize; i++)
	{
		//	printf("%x", msg[i]);
		g_suci.ecc_pub_key[i - start] = (uint8_t)msg[i];
	}
	//	printf("\n");
#ifdef DebugAkmaInfo
	printf("SEAF print suci\n");
	printf("\t mcc_mnc:");
	for (int i = 0; i < sizeof(g_suci.mcc_mnc); i++)
	{
		printf("%02x", g_suci.mcc_mnc[i]);
	}
	printf("\n\t msin:");
	for (int i = 0; i < sizeof(g_suci.msin); i++)
	{
		printf("%02x", g_suci.msin[i]);
	}
	printf("\n\t msin:");
	for (int i = 0; i < sizeof(g_suci.ecc_pub_key); i++)
	{
		printf("%02x", g_suci.ecc_pub_key[i]);
	}
	printf("\n");
#endif
	// Authenticate Request (AUSF)
#ifdef measure
	printf("Tout: %lu \n", clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif
	Nausf_UEAuthenticationRequest(se_av, &g_suci, sn_name);
#ifdef measure
	printf("Tin: %lu \n", clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif
#ifdef testb
	printf("SEAF: SE_AV authentication vector\n");
	printf("\t rand: ");
	for (int i = 0; i < 16; i++)
	{
		printf("%x", se_av->rand[i]);
	}
	printf("\n");
	printf("\t autn: ");
	for (int i = 0; i < 16; i++)
	{
		printf("%x", se_av->autn[i]);
	}
	printf("\n");
	printf("\t hxres_star: ");
	for (int i = 0; i < 32; i++)
	{
		printf("%x", se_av->hxres_star[i]);
	}
	printf("\n");
#endif

#ifdef measurefct
	z = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n", y);
	printf("B: %lu \n", z);
	printf("Nseaf_UEAuthenticationRequest Duration %lu ns\n", z - y);
#endif
#ifdef measure
	printf("Tout: %lu \n", clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif
#ifdef showmethod
	printm(ebene, "SEAF: Nseaf_UEAuthenticationRequest End\n");
#endif
	return;
}

static void Nseaf_UEAuthenticationResponse(unsigned char *res)
{
#ifdef showmethod
	printm(ebene, "SEAF: Nseaf_UEAuthenticationResponse Begin\n");
#endif
#ifdef measurefct
	uint64_t y, z;
	y = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef measure
	printf("Tin: %lu \n", clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif
	uint8_t res_star[32], hres_star[32];
#ifdef testb
	printf("\tRES: ");
#endif
	for (int i = 0; i < 39; i++)
	{
#ifdef testb
		printf("%x", res[i]);
#endif
		if (i > 6)
		{
			res_star[i - 7] = res[i];
		}
	}
#ifdef testb
	printf("\n");
	printf("\tRES_Star: ");
	for (int i = 0; i < 32; i++)
	{
		printf("%x", res_star[i]);
	}
	printf("\n");
#endif
	// Calculate HRES* and
	calc_HRESstar(&hres_star, res_star, g_se_av.rand);
	// Compare HXRES*
	int hrescmp = memcmp(hres_star, g_se_av.hxres_star, 32);
	if (hrescmp == 0)
	{
		printf("hres_star/hxres_star compare successful!\n");
	}
	else
	{
		printf("hres_star/hxres_star compare NOT successful!\n");
	}

	int ret;
#ifdef measure
	printf("Tout: %lu \n", clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif
	ret = Nausf_UEAuthenticationResponse(res_star, &g_supi, &kseaf); // Result, [SUPI], Kseaf
	printf("Authentication Result: %d \n", ret);
#ifdef measure
	printf("Tin: %lu \n", clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif

#ifdef measurefct
	z = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n", y);
	printf("B: %lu \n", z);
	printf("Nseaf_UEAuthenticationResponse Duration %lu ns\n", z - y);
#endif
#ifdef measure
	printf("Tout: %lu \n", clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif
#ifdef showmethod
	printm(ebene, "SEAF: Nseaf_UEAuthenticationResponse End\n");
#endif
}

static void seaf_init()
{
#ifdef showmethod
	printm(ebene, "SEAF: seaf_init\n");
#endif
	ausf_init();
}

static void seaf_close()
{
#ifdef showmethod
	printf("SEAF: seaf_close\n");
#endif
}

int main(void)
{
	printm(ebene, "Start SEAF\n");
	char *RSA_PK_AAnF;
	size_t RSA_pubkey_len; 
	seaf_init();
	// Variable declaration
	uint64_t a, b;
	struct sockaddr_in svAddr;
	struct sockaddr_in recvAddr;
	socklen_t addrlen = sizeof(recvAddr);
	int sv;
	int recvlen;
	unsigned char buf[BUFSIZE];
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
	svAddr.sin_port = htons(SV_PORT);

	if (bind(sv, (struct sockaddr *)&svAddr, sizeof(svAddr)) < 0)
	{
		perror("Bind failed");
		return 0;
	}

	printf("SEAF-server started, listening on port %d\n", SV_PORT);

	// loop for receiving
	for (int idx = 0; idx < 4; idx++)
	{
		printf("waiting on port %d\n", SV_PORT);
		recvlen = recvfrom(sv, buf, BUFSIZE, 0, (struct sockaddr *)&recvAddr, &addrlen);
		if (recvlen > 0)
		{
			buf[recvlen] = 0;
#ifdef test
			printf("received message (%d bytes) :", recvlen);
			for (int i = 0; i < recvlen; i++)
			{
				printf("%02x", buf[i]);
			}
			printf("\n");
#endif
			if (strncmp(buf, "getHNPK", 7) == 0)
			{
				// strcpy(buf, homeNetworkPublicKey); //,65);
				int offset = 0;
				memcpy(buf + offset, homeNetworkPublicKey, sizeof(homeNetworkPublicKey));
				// buf[65] = 0;
				offset += sizeof(homeNetworkPublicKey);
#ifdef DebugAkmaInfo
    // printf("\nSEAF print s_RSA_PK_AAnF = %d \n", PK_AAnF_len);
    // printf("\n%s\n", PK_AAnF);
	// BIO_dump_fp(stdout, (const char *)PK_AAnF, PK_AAnF_len);
#endif	
				// memcpy(buf + offset, PK_AAnF, PK_AAnF_len);
				// offset += PK_AAnF_len;
				// if (sendto(sv, buf, sizeof(homeNetworkPublicKey), 0, (struct sockaddr *)&recvAddr, addrlen) < 0)
				if (sendto(sv, buf, offset, 0, (struct sockaddr *)&recvAddr, addrlen) < 0)
					perror("Send HNPK");
			}
			if (strncmp(buf, "AuthReq", 7) == 0)
			{

				Nseaf_UEAuthenticationRequest(&g_se_av, buf);
// TODO: Response to UE, add ngKSI
// Create buf = Rand || AUTN (||ngKSI)
#ifdef test
				printf("SEAF: SE_AV authentication vector\n");
				printf("\t rand: ");
				for (int i = 0; i < 16; i++)
				{
					printf("%x", se_av.rand[i]);
				}
				printf("\n");
				printf("\t autn: ");
				for (int i = 0; i < 16; i++)
				{
					printf("%x", se_av.autn[i]);
				}
				printf("\n");
				printf("\t hxres_star: ");
				for (int i = 0; i < 32; i++)
				{
					printf("%x", se_av.hxres_star[i]);
				}
				printf("\n");
#endif
				uint8_t tmp[32];
				for (int i = 0; i < 32; i++)
				{
					if (i < 16)
					{
						tmp[i] = g_se_av.rand[i];
					}
					else
					{
						tmp[i] = g_se_av.autn[i - 16];
					}
				}
				memcpy(buf, tmp, sizeof(tmp));

				buf[32] = 0;

#ifdef test
				printf("BUFFER: ");
				for (int i = 0; i < sizeof(tmp); i++)
				{
					printf("%x", buf[i]);
				}
				printf("\n");
#endif
#ifdef measure
				printf("Tout: %lu \n", clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif
				if (sendto(sv, buf, sizeof(tmp), 0, (struct sockaddr *)&recvAddr, addrlen) < 0)
					perror("AuthenticationRequest");
			}
			else if (strncmp(buf, "AuthRes", 7) == 0)
			{

				Nseaf_UEAuthenticationResponse(buf);
				printf("******** Primary Authentication in 5G End (i.e., 5G-AKA Ends)*******\n\n\n\n");

				/*AKMA Begin
				 */
				printf("**************** 5G-AKMA Begin ***************\n\n");
				printf("-------AKMA Phase 1:Deriving K_AKMK after primary authentication---\n\n\n");
				Nudm_UEAuthentication_Get_Request_AUSF(&g_supi, &g_suci);
			}
			/*AF send to SEAF: "AKMAKeyRequest" + a_kid_t + af_id_t +
				CT_UE_AAnF_Len(4 bytes) + CT_UE_AAnF + CT_UE_AAnF_TAG(2 bytes) */
			else if (strncmp(buf, "AKMAKeyRequest", 14) == 0)
			{
#ifdef CommCosts
				printf("AKMA step 7 (AF-->AAnF) AAnf receive message from AF(%d bytes)\n", recvlen);
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
				a_kid_t a_kid;
				af_id_t af_id;
				int offset = 14;
				// Parse2AKID(buf + 14, recvlen - 14 - sizeof(af_id_t), &a_kid);
				// Parse2AFID(buf + 14 + sizeof(a_kid_t), recvlen - 14 - sizeof(a_kid_t), &af_id);
				Parse2AKID(buf + offset, sizeof(a_kid_t), &a_kid);
				offset += sizeof(a_kid_t);
				Parse2AFID(buf + offset, sizeof(af_id_t), &af_id);
				offset += sizeof(af_id_t);
#ifdef measureAKMAfct
				z = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
				printf("AAnF step 7 Duration %lu ns\n", z - y);
#endif
#ifdef measureAKMAfct
				uint64_t y2, z2;
				y2 = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
				unsigned char str_SEnc_CT_UE_AAnF_Len[5];
				memset(str_SEnc_CT_UE_AAnF_Len, 0x00, sizeof(str_SEnc_CT_UE_AAnF_Len));
                unsigned int SEnc_CT_UE_AAnF_Len = 0;
                memcpy(str_SEnc_CT_UE_AAnF_Len, buf + offset, 4);
                offset += 4;
                SEnc_CT_UE_AAnF_Len = atoi(str_SEnc_CT_UE_AAnF_Len);
                unsigned char SEnc_CT_UE_AAnF[BUFSIZ];
                memcpy(SEnc_CT_UE_AAnF, buf + offset, SEnc_CT_UE_AAnF_Len);
                offset += SEnc_CT_UE_AAnF_Len;
				unsigned char CT_UE_AAnF_TAG[TAG_SIZE];
				memcpy(CT_UE_AAnF_TAG, buf + offset, TAG_SIZE);
                offset += TAG_SIZE;

				// size_t enc_CT_UE_AAnF_len = 16;
				// unsigned char enc_CT_UE_AAnF[enc_CT_UE_AAnF_len];
				// memcpy(enc_CT_UE_AAnF, buf + offset, enc_CT_UE_AAnF_len);


#ifdef DebugAkmaInfo
				printf("SEAF print af_id.fqdn:");
				for (int i = 0; i < sizeof(af_id.fqdn); i++)
				{
					printf("%02x", af_id.fqdn[i]);
				}
				printf("\n");
				printf("SEAF print af_id.uaid:");
				for (int i = 0; i < sizeof(af_id.uaid); i++)
				{
					printf("%02x", af_id.uaid[i]);
				}
				printf("\n");
				printf("SEAF print SEnc_CT_UE_AAnF(%d):", SEnc_CT_UE_AAnF_Len);
				for (int i = 0; i < SEnc_CT_UE_AAnF_Len; i++)
				{
					printf("%02x", SEnc_CT_UE_AAnF[i]);
				}
				printf("\n");
				printf("SEAF print CT_UE_AAnF_TAG(%d):", TAG_SIZE);
				for (int i = 0; i < TAG_SIZE; i++)
				{
					printf("%02x", CT_UE_AAnF_TAG[i]);
				}
				printf("\n");
#endif

#ifdef measureAKMAfct
				z2 = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
				printf("AAnF step 7 akma+ add Duration %lu ns\n", z2 - y2);
#endif
				unsigned char send_buf[BUFSIZE];
				memset(send_buf, 0x00, sizeof(send_buf));
				int send_len = 0;
				// send_buf = k_af_t + timeval + supi + Res_AAnF_len(4 Bytes) + Res_AAnF + Res_AAnF_sign
				Naanf_AKMA_ApplicationKey_GetRequest_AAnF(&a_kid, &af_id, 
					SEnc_CT_UE_AAnF, SEnc_CT_UE_AAnF_Len, CT_UE_AAnF_TAG,
					send_buf, &send_len);

#ifdef DebugAkmaInfo
				printf("SEAF response to AF (%d):", send_len);
				for (int i = 0; i < send_len; i++)
				{
					printf("%02x", send_buf[i]);
				}
				printf("\n");
#endif

				if (sendto(sv, send_buf, send_len, 0, (struct sockaddr *)&recvAddr, addrlen) < 0)
					perror("AKMAKeyRequest(AAnF -> AF) response error");

				printf("******** 5G-AKMA Ends*******\n\n\n\n");
			}
		}
		else
			printf("Message Unknown\n");

		// Answer
		// sprintf(buf, "ack");
	}

	b = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// #ifdef measure
	//	printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	// #endif
	// #ifdef measure
	//	printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	//	printf("A: %lu \n",a);
	//	printf("B: %lu \n",b);
	//	printf("Duration %lu ns\n",b-a);
	// #endif
	close(sv);
	free(PK_AAnF);
	free(SK_AAnF);
	// printm(ebene, "Authentication End\n");
	return EXIT_SUCCESS;
}
