/*
 * AUSF.c
 *
 */

#include "AUSF.h"
#include "UDM.h"
#include <openssl/sha.h>
#include <sys/time.h>
#include <time.h>
#include "genericFunctions.h"
#include <string.h>
#include <stdio.h>
#include "AAnF.h"
#include "sidf.h"

static char* serving_names[9][10];
static const char allowed_sn_names[] = "5G:NTNUnet";
static int sn_counter = 0;
static he_av_t he_av;
static av_t av;
static k_akma_t g_k_akma;
static a_kid_t g_a_kid;
static rid_t g_rid;
static int ebene = 1;
// return 1 when SNName is verified. 0 if not
static int check_SNName(sn_name_t* sn_name){
#ifdef showmethod
	printm(ebene,"AUSF: check_SNName\n");
#endif
#ifdef measurefct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	int ret = 1;
	int a = strcmp(sn_name, allowed_sn_names);
	if(a!=0){
		ret=0;
	}
#ifdef measurefct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",y);
	printf("B: %lu \n",z);
	printf("check_SNName Duration %lu ns\n",z-y);
#endif
	return ret;
}

static int store_SNName(sn_name_t* sn_name){
#ifdef showmethod
	printm(ebene,"AUSF: storeSNName\n");
#endif
#ifdef measurefct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	int ret = 0;
	strcpy(serving_names[sn_counter],sn_name);
	if(sn_counter<sizeof(serving_names)){
		sn_counter++;
		ret = -1;
	} else {
		printf("Storage full!");
	}

#ifdef measurefct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",y);
	printf("B: %lu \n",z);
	printf("store_SNName Duration %lu ns\n",z-y);
#endif
	return ret;
}

static void store_Kausf(uint8_t* k_ausf){

}

static void derive_Kseaf(uint8_t* k_seaf, uint8_t* k_ausf, sn_name_t sn_name){
#ifdef showmethod
	printm(ebene,"AUSF: deriveK_seaf\n");
#endif
#ifdef measurefct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	// K_seaf derivation function (TS33.501, Annex A.6)
	int n = 1;

	uint8_t fc = 0x6c;
	const char *pn[n];
	uint16_t ln[n];
	pn[0] = sn_name;
	ln[0] = SIZE_SN_NAME;


	genericKeyDerivation(k_ausf, sizeof(k_ausf),fc,pn,ln,n,k_seaf);


#ifdef measurefct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",y);
	printf("B: %lu \n",z);
	printf("derive_Kseaf Duration %lu ns\n",z-y);
#endif
	return;
}

static void calc_HXRESstar(uint8_t hxres_star[16], uint8_t xres_star[32], uint8_t rand[16]){
#ifdef showmethod
	printm(ebene,"AUSF: computeHXRES\n");
#endif
#ifdef measurefct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef testb
	printf("\t res_star: ");
	for(int i = 0; i<32;i++){
		printf("%x",xres_star[i]);
	}
	printf("\n");
	printf("\t rand: ");
	for(int i = 0; i<16;i++){
		printf("%x",rand[i]);
	}
	printf("\n");
#endif
	// HRES* and HXRES* derivation function (TS33.501, Annex A.5)
	int n = 2;

	int rand_size = 16, xres_star_size = 32;
	uint8_t fc = NULL;
	unsigned char s[rand_size + xres_star_size];
	uint16_t ln[n];
	for(int i=0; i<rand_size;i++){
		s[i] = (unsigned char)rand[i];
	}
	for(int i=0; i<xres_star_size;i++){
		s[rand_size + i] = (unsigned char)xres_star[i];
	}

	const unsigned char s_tmp[sizeof(s)], md[32];
	memcpy(s_tmp, s, sizeof(s));
	//SHA256
	SHA256(s, sizeof(s), md);
	for(int i=0; i< sizeof(md);i++){
		hxres_star[i]= (uint8_t) md[i];

	}

#ifdef measurefct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",y);
	printf("B: %lu \n",z);
	printf("calc_HXRESstar Duration %lu ns\n",z-y);
#endif
	return;
}


void ausf_init(){
#ifdef showmethod
	printm(ebene,"AUSF: initAUSF\n");
#endif
	// aanf_init();
	
	udm_init();
}

void ausf_close(){}

void Nausf_UEAuthenticationRequest(se_av_t* se_av, suci_t* suci, sn_name_t* sn_name){
#ifdef showmethod
	printm(ebene,"AUSF: Nausf_UEAuthenticationRequest Begin\n");
#endif
#ifdef measurefct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef measure
	printf("Tin: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif

	// Check serving network name
	if(check_SNName(sn_name)){
		// Store received serving name
		store_SNName(sn_name);
#ifdef testb
		puts("SUCI.msin");
			for(int i=0; i<sizeof(suci->msin);i++){
				printf("%x", suci->msin[i]);
			}
			puts("\n");
			puts("SUCI.eccpubkey");
			for(int i=0; i<sizeof(suci->ecc_pub_key);i++){
				printf("%x", suci->ecc_pub_key[i]);
			}
			puts("\n");
#endif
		//Request to UDM
#ifdef measure
	printf("Tout: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif

		Nudm_UEAuthenticationRequest(&he_av, suci, sn_name);

#ifdef measure
	printf("Tin: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif
		#ifdef testb
			printf("AUSF: got AV\n");
		#endif

		memcpy(av.autn, he_av.autn, sizeof(he_av.autn));

		av.method = he_av.method;

		memcpy(av.rand, he_av.rand, sizeof(he_av.rand));

		memcpy(av.supi.mcc_mnc,he_av.supi.mcc_mnc,sizeof(he_av.supi.mcc_mnc));

		memcpy(av.supi.msin,he_av.supi.msin,sizeof(he_av.supi.msin));

		// Calculate HXRES*
		calc_HXRESstar(&av.hxres_star, he_av.xres_star, he_av.rand);
		derive_Kseaf(av.k_seaf, he_av.k_ausf, sn_name);

		// Store XRES*
		store_Kausf(he_av.k_ausf);
		//memcpy(se_av->rand, av.rand, sizeof(av.rand));
		for(int i=0; i<sizeof(av.rand); i++){
			se_av->rand[i] = av.rand[i];
		}

		//memcpy(se_av->autn, av.autn, sizeof(av.autn));
		for(int i=0; i<sizeof(av.autn); i++){
			se_av->autn[i] = av.autn[i];
		}
		//memcpy(se_av->hxres_star, av.hxres_star, sizeof(av.hxres_star));
		for(int i=0; i<sizeof(av.hxres_star); i++){
			se_av->hxres_star[i] = av.hxres_star[i];
		}
#ifdef testb
	printf("AUSF: AV authentication vector\n");
	printf("\t method: %d", av.method);
	printf("\n");
	printf("\t rand: ");
	for(int i=0; i<16; i++){
		printf("%x",av.rand[i]);
	}
	printf("\n");
	printf("\t autn: ");
	for(int i=0; i<16; i++){
		printf("%x",av.autn[i]);
	}
	printf("\n");
	printf("\t hxres_star: ");
	for(int i=0; i<32; i++){
		printf("%x",av.hxres_star[i]);
	}
	printf("\n");
	printf("\t k_seaf: ");
	for(int i=0; i<32; i++){
		printf("%x",av.k_seaf[i]);
	}
	printf("\n");
	printf("\t supi: ");
	for(int i=0; i<8; i++){
		if(i<3){
			printf("%x", av.supi.mcc_mnc[i]);
		} else {
			printf("%x", av.supi.msin[i-3]);
		}
	}
	printf("\n");
#endif

#ifdef testb
	printf("AUSF: SE_AV authentication vector\n");
	printf("\t rand: ");
	for(int i=0; i<16; i++){
		printf("%x",se_av->rand[i]);
	}
	printf("\n");
	printf("\t autn: ");
	for(int i=0; i<16; i++){
		printf("%x",se_av->autn[i]);
	}
	printf("\n");
	printf("\t hxres_star: ");
	for(int i=0; i<32; i++){
		printf("%x",se_av->hxres_star[i]);
	}
	printf("\n");
#endif

	}else {
		//return "SN is not authorized!";
#ifdef measure
	printf("Tout: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif
		return;
	}
#ifdef measure
	printf("Tout: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif

#ifdef measurefct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",y);
	printf("B: %lu \n",z);
	printf("Nausf_UEAuthenticationRequest Duration %lu ns\n",z-y);
#endif
#ifdef showmethod
	printm(ebene,"AUSF: Nausf_UEAuthenticationRequest End\n");
#endif
	return;
}



int Nausf_UEAuthenticationResponse(uint8_t *res_star, supi_t *supi, uint8_t *kseaf){
#ifdef showmethod
	printm(ebene,"AUSF: Nausf_UEAuthenticationResponse Begin\n");
#endif
#ifdef measurefct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef measure
	printf("Tin: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif
	// Res Verification
	int result = 0;
	if(memcmp(he_av.xres_star, res_star, 32)==0){
		result =1;
		printf("res_star/xres_star compare successful\n");
		memcpy(supi->mcc_mnc, he_av.supi.mcc_mnc, sizeof(he_av.supi.mcc_mnc));
		memcpy(supi->msin, he_av.supi.msin, sizeof(he_av.supi.msin));
		memcpy(kseaf, av.k_seaf, sizeof(av.k_seaf));
		struct timeval tv;
		gettimeofday(&tv,NULL);
#ifdef measure
	printf("Tout: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif
		Nudm_AuthenticationSuccessful(supi, tv, 2, serving_names[sn_counter-1]);
#ifdef measure
	printf("Tin: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif
	} else {
		result = 0;
		printf("res_star/xres_star compare NOT successful\n");
	}
#ifdef measure
	printf("Tout: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif

#ifdef measurefct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",y);
	printf("B: %lu \n",z);
	printf("Nausf_UEAuthenticationResponse Duration %lu ns\n",z-y);
#endif
#ifdef showmethod
	printm(ebene,"AUSF: Nausf_UEAuthenticationResponse End\n");
#endif
	return result;
}


// AKMA Begin

/*
supi_t * supi: input
suci_t *suci : inpuit
*/
void Nudm_UEAuthentication_Get_Request_AUSF(supi_t * supi, suci_t *suci){
#ifdef showAKMAmethod
    printf("AKMA step 1 (AUSF-->UDM) Nudm_UEAuthentication_Get_Request_AUSF(supi, suci) Send \n");
#endif
#ifdef CommCosts 
	int costLen = sizeof(supi_t) + sizeof(suci_t) ;
	printf("\nAKMA step 1 (AUSF-->UDM) AUSF send message to UDM (%d bytes)\n", costLen);
#endif
#ifdef measurefct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif


#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	uint8_t AKMA_Ind;


#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("AUSF step 1 Duration %lu ns\n",z-y);
#endif

// #ifdef CommCosts 
// 	int costLen = sizeof(supi_t) + sizeof(suci_t);
// 	printf("\nAKMA step 1(AUSF-->UDM) AUSF send message to UDM (%d bytes)\n", costLen);
// #endif

	Nudm_UEAuthentication_Get_Request_UDM(supi, suci, &he_av, &AKMA_Ind, &g_rid);

#ifdef DebugAkmaInfo
	printf("\n");
	printf("\t Nudm_UEAuthentication_Get_Request_AUSF supi: ");
	for(int i=0; i<8; i++){
		if(i<3){
			printf("%x", supi->mcc_mnc[i]);
		} else {
			printf("%x", supi->msin[i-3]);
		}
	}
	printf("\n");
#endif

	Nudm_UEAuthentication_Get_Response_AUSF(&he_av, &AKMA_Ind, &g_rid);	

#ifdef DebugAkmaInfo
	printf("\nAUSF print he_av->k_ausf: ");
	for(int i=0;i<sizeof(he_av.k_ausf);i++){
		printf("%02x",he_av.k_ausf[i]);
	}
	printf("\n");
	printf("AUSF print supi\n");
	printf("\t mcc_mnc:");
	for(int i=0; i< sizeof(supi->mcc_mnc);i++){
		printf("%02x", supi->mcc_mnc[i]);
	}
	printf("\n\t msin:");
	for(int i=0; i< sizeof(supi->msin);i++){
		printf("%02x", supi->msin[i]);
	}
	printf("\n");
#endif

#ifdef measureAKMAfct
	uint64_t y0,z0;
	y0=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	// calc_KAKMA_from_KAUSF(he_av.k_ausf, supi, &g_k_akma);

	// calc_AKID_from_KAUSF(he_av.k_ausf, supi, &g_a_kid);

	size_t akma_pair_size = 1;

	akma_pair_t akma_pair[akma_pair_size];

	unsigned char currentDate[9];
	getCurrentDate(currentDate);

	for (int i = 0; i < akma_pair_size; i++)
	{
		calc_KAKMA_from_KAUSF_2(he_av.k_ausf, supi, i, currentDate, &(akma_pair[i].k_akma));

		calc_AKID_from_KAUSF_2(he_av.k_ausf, supi, i, currentDate, &(akma_pair[i].a_kid));
	}

#ifdef measureAKMAfct
	z0=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	printf("AUSF step 3a, 3b Duration %lu ns\n",z0-y0);
#endif

	Naanf_AKMA_AnchorKey_Register_Request_AUSF_2(akma_pair, akma_pair_size);

	Naanf_AKMA_AnchorKey_Register_Response_AUSF();

#ifdef measurefct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",y);
	printf("B: %lu \n",z);
	printf("Nudm_UEAuthentication_Get_Request_AUSF Duration %lu ns\n",z-y);
#endif

}

/*
he_av_t * he_av : input
uint8_t AKMA_Ind : input
rid_t *rid : input
*/
void Nudm_UEAuthentication_Get_Response_AUSF(he_av_t * he_av, uint8_t AKMA_Ind, rid_t *rid){
#ifdef showAKMAmethod
    printf("AKMA step 2 (UDM-->AUSF) Nudm_UEAuthentication_Get_Response_AUSF(he_av,AKMA_Ind,rid) receive \n");
#endif
#ifdef CommCosts 
	int costLen = sizeof(he_av_t) + sizeof(uint8_t) + sizeof(rid_t);
	printf("\nAKMA step 2 (UDM-->AUSF) AUSF receive message from UDM (%d bytes)\n", costLen);
#endif
#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("AUSF step 2 Duration %lu ns\n",z-y);
#endif

}

/*
k_ausf:input
supi:input
k_akma:output
*/

static void calc_KAKMA_from_KAUSF(k_ausf_t *k_ausf, supi_t *supi, k_akma_t *k_akma){
#ifdef showAKMAmethod
    printf("AKMA step 3a (AUSF calc) calc_KAKMA_from_KAUSF(k_ausf,supi,k_akma) \n");
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

	printf("AUSF befor AKMA print k_ausf(%d): ", SIZE_K_AUSF);
	for(int i=0;i<sizeof(k_ausf_t);i++){
		printf("%02x",k_ausf->k_ausf[i]);
	}
	printf("\n");
	printf("AUSF befor AKMA print fc: ");
	for(int i=0;i<sizeof(fc);i++){
		printf("%02x",fc);
	}
	printf("\n");
	printf("AUSF befor AKMA print pn: ");
	for(int i=0;i<sizeof(pn);i++){
		printf("%02x",pn[i]);
	}
	printf("\n");
	printf("AUSF befor AKMA print ln: ");
	for(int i=0;i<2;i++){
		printf("%02x",ln[i]);
	}
	printf("\n");
#endif

	// uint8_t output[32];
	// memset(output, 0xff, sizeof(output));
	// printf("\n");
	// printf("AUSF before genericKeyDerivation print output: ");
	// for(int i=0; i<32; i++){
	// 	printf("%02x",output[i]);
	// }
	// printf("\n");

	// printf("AUSF before genericKeyDerivation print output address 2 %p\n",output);

	genericKeyDerivation(k_ausf->k_ausf,SIZE_K_AUSF,fc,(uint8_t*)pn,ln,2,k_akma->k_akma);

#ifdef DebugAkmaInfo
	printf("\n");
	printf("AUSF after genericKeyDerivation print k_akma->k_akma: ");
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
	printf("AUSF step 3a Duration %lu ns\n",z-y);
#endif
	
}

/*
k_ausf:input
supi:input
k_akma:output
*/

void calc_KAKMA_from_KAUSF_2(k_ausf_t *k_ausf, supi_t *supi, 
		int counter, unsigned char *date, k_akma_t *k_akma){
#ifdef showAKMAmethod
    printf("AKMA step 3a (AUSF calc) calc_KAKMA_from_KAUSF(k_ausf,supi,k_akma) \n");
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


	genericKeyDerivation(k_ausf->k_ausf,SIZE_K_AUSF,fc,(uint8_t*)pn,ln,ln_len,k_akma->k_akma);
#ifdef measureAKMAfct2
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	printf("AUSF step 3a Duration %lu ns\n",z-y);
#endif
#ifdef DebugAkmaInfo
	printf("\n");
	printf("AUSF after genericKeyDerivation print k_akma->k_akma: ");
	for(int i=0; i<32; i++){
		printf("%02x",k_akma->k_akma[i]);
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
    printf("AKMA step 3b(AUSF calc) calc_AKID_from_KAUSF(k_ausf,supi,a_kid) begin \n");
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
	genericKeyDerivation(k_ausf->k_ausf,SIZE_K_AUSF,fc,(uint8_t*)pn,ln,2,a_tid);

	memcpy((a_kid->username).a_tid, a_tid, sizeof(a_tid));
	memcpy(&(a_kid->username).rid, &g_rid, sizeof(g_rid));
	memcpy(a_kid->at, "@", 1);
	memset(a_kid->realm, 0xFF, sizeof(a_kid->realm));

#ifdef DebugAkmaInfo
	print_akid(&a_kid);
#endif

#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("AUSF step 3b Duration %lu ns\n",z-y);
#endif
}

/*
k_ausf:input
supi:input
counter:input
date:input
a_kid:output
*/
void calc_AKID_from_KAUSF_2(k_ausf_t *k_ausf, supi_t *supi, 
		int counter, unsigned char *date, a_kid_t *a_kid){
#ifdef showAKMAmethod
    printf("AKMA step 3b(AUSF calc) calc_AKID_from_KAUSF(k_ausf,supi,a_kid) begin \n");
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

	memcpy(pn, "A-TID", SIZE_K_ATID);
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
	
	genericKeyDerivation(k_ausf->k_ausf,SIZE_K_AUSF,fc,(uint8_t*)pn,ln,ln_len,a_tid);

// #ifdef DebugAkmaInfo
// 	printf("AUSF printf a_tid:");
// 	for(int i=0;i<sizeof(a_tid); i++) {
// 		printf("%02x", a_tid[i]);
// 	}
// 	printf("\n");
// 	printf("AUSF printf g_rid:");
// 	for(int i=0;i<sizeof(g_rid.rid); i++) {
// 		printf("%02x", g_rid.rid[i]);
// 	}
// 	printf("\n");
// #endif	

	memcpy((a_kid->username).a_tid, a_tid, sizeof(a_tid));
	memcpy(&(a_kid->username).rid, &g_rid, sizeof(g_rid));
	memcpy(a_kid->at, "@", 1);
	memset(a_kid->realm, 0xFF, sizeof(a_kid->realm));
#ifdef measureAKMAfct2
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	printf("AUSF step 3b Duration %lu ns\n",z-y);
#endif
#ifdef DebugAkmaInfo
	print_akid(a_kid);
#endif

}

/*
supi_t * supi : input 
a_kid_t * a_kid : input
k_akma_t * k_akma : input
*/
void Naanf_AKMA_AnchorKey_Register_Request_AUSF(supi_t * supi, a_kid_t * a_kid, k_akma_t * k_akma)
{
#ifdef showAKMAmethod
    printf("AKMA step 4 (AUSF-->AAnF) Naanf_AKMA_AnchorKey_Register_Request_AUSF(supi, a_kid) send \n");
#endif

#ifdef CommCosts 
	int costLen = sizeof(supi_t) + sizeof(a_kid_t) + sizeof(k_akma_t);
	printf("\nAKMA step 4 (AUSF-->AAnF) AUSF send message to AAnF (%d bytes)\n", costLen);
#endif

#ifdef measurefct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("AUSF step 4 Duration %lu ns\n",z-y);
#endif

	// Naanf_AKMA_AnchorKey_Register_Request_AAnF(supi, a_kid, &g_k_akma);
	Naanf_AKMA_AnchorKey_Register_Request_AAnF(supi, a_kid, k_akma);

// #ifdef CommCosts 
// 	costLen = 0;
// 	printf("\nAKMA step 5 (AAnF-->AUSF) AUSF receive message from AAnF (%d bytes)\n", costLen);
// #endif

// #ifdef measureAKMAfct
// 	uint64_t y1,z1;
// 	y1=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
// #endif

// #ifdef measureAKMAfct
// 	z1=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
// 	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
// 	// printf("A: %lu \n",y1);
// 	// printf("B: %lu \n",z1);
// 	printf("AUSF step 5 Duration %lu ns\n",z1-y1);
// #endif

}

/*
supi_t * supi : input 
a_kid_t * a_kid : input
k_akma_t * k_akma : input
*/
void Naanf_AKMA_AnchorKey_Register_Request_AUSF_2(akma_pair_t * p_akma_pair, size_t akma_pair_size)
{
#ifdef showAKMAmethod
    printf("AKMA step 4 (AUSF-->AAnF) Naanf_AKMA_AnchorKey_Register_Request_AUSF_2(p_akma_pair, akma_pair_size) send \n");
#endif

#ifdef CommCosts 
	int costLen = sizeof(akma_pair_t) * akma_pair_size;
	printf("\nAKMA step 4 (AUSF-->AAnF) AUSF send message to AAnF (%d bytes)\n", costLen);
#endif

#ifdef measurefct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("AUSF step 4 Duration %lu ns\n",z-y);
#endif

	// Naanf_AKMA_AnchorKey_Register_Request_AAnF(supi, a_kid, &g_k_akma);
	// Naanf_AKMA_AnchorKey_Register_Request_AAnF(supi, a_kid, k_akma);
	Naanf_AKMA_AnchorKey_Register_Request_AAnF_2(p_akma_pair, akma_pair_size);


}

void Naanf_AKMA_AnchorKey_Register_Response_AUSF(){
#ifdef showAKMAmethod
    printf("AKMA step 5 (AAnF-->AUSF) Naanf_AKMA_AnchorKey_Register_Response_AUSF() receive \n");
#endif

#ifdef CommCosts 
	int costLen = 1;
	printf("\nAKMA step 5 (AAnF-->AUSF) AUSF receive message from AAnF (%d bytes)\n", costLen);
#endif

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("AUSF step 5 Duration %lu ns\n",z-y);
#endif
}