/*
 * UDM.c
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "UDM.h"
#include "ffunction.h"
#include "genericFunctions.h"
#include "sidf.h"
#include <sys/time.h>
#include <time.h>
#include "av_types.h"

#define AKA_EAP 1;
#define AKA_5G 2;

#define UE_STORAGE_SIZE 3
#define UE_SUPI_A 0x0123456789abcde

static int ebene = 2;

static he_av_t g_he_av;

#define udm_akid_pair_size 1

static udm_akid_pair_t udm_akid_pair[udm_akid_pair_size];

#define udm_akid_pair_max_size 10000
static size_t udm_akid_pair_index = 0;
static udm_akid_pair_t udm_akid_pair_db[udm_akid_pair_max_size];


// Dataset for one UE
typedef struct{
	supi_t supi;			// SUPI for
	uint8_t authMethod;		// Authentication methode.
	uint8_t sqn[6];			// Sequence number
	uint8_t key[SIZE_K]; 	// 128 (or 256) bits long, long-term key
} ue_unit_t;

// Storage for UE-Data
static ue_unit_t ue_storage[UE_STORAGE_SIZE];
/* initialize the Storage of UDM
 * TODO: static data in function -> in storage
 */
static void initUEStorage(){
#ifdef showmethod
	printm(ebene,"UDM: initUEStorage\n");
#endif
	for(int idx=0; idx<UE_STORAGE_SIZE; idx++){
		//strcpy(ue_storage[idx].supi, UE_SUPI_A);
		for(int jdx=0; jdx<3;jdx++){
			ue_storage[idx].supi.mcc_mnc[jdx]=idx;
		}
		for(int jdx=0; jdx<5;jdx++){
			ue_storage[idx].supi.msin[jdx]=idx;
		}
		ue_storage[idx].authMethod = AKA_5G;
		for(int jdx = 0; jdx < sizeof(ue_storage[idx].sqn);jdx++){
			ue_storage[idx].sqn[jdx] = 0;
		}

		for(int jdx=0; jdx<SIZE_K;jdx++){
			ue_storage[idx].key[jdx]=idx;
		}
	}
}


int getIndex(supi_t supi){
#ifdef showmethod
	printm(ebene,"UDM: getIndex\n");
#endif
	for(int idx=0; idx<UE_STORAGE_SIZE; idx++){
		if(memcmp(ue_storage[idx].supi.mcc_mnc, supi.mcc_mnc, 3)==0){
			printf("mcc_mnc is equal\n");
			if(memcmp(ue_storage[idx].supi.msin, supi.msin, 5)==0){
				printf("msin is equal\n");
				return idx;
			}

		}
	}
	return -1;
}


void generate_Autn(int stor_index, uint8_t rand[16], uint8_t autn[16]){
#ifdef showmethod
	printm(ebene,"UDM: generate_Autn\n");
#endif
#ifdef measurefct
	uint64_t a,b;
	a=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	// AUTN = SQN XOR AK || AMF || MAC
	uint8_t amf[2] = {0x80,0x00};
	uint8_t mac_a[8];
	uint8_t ak[6];
	int i;

	f1(ue_storage[stor_index].key, rand, ue_storage[stor_index].sqn, amf, mac_a);
	uint8_t res[8], ck[16], ik[16];
	f2345(ue_storage[stor_index].key, rand, res, ck, ik, ak);
	for(i = 0; i<6;i++){
		autn[i]= ue_storage[stor_index].sqn[i] ^ ak[i];
	}

	for(i=6;i<8;i++){
		autn[i]= amf[i-6];
	}

	for(i=8;i<16;i++){
		autn[i]= mac_a[i-8];
	}
#ifdef testb
	printm(ebene,"UDM: Autn\n");
	printf("\t Autn: ");
		for(i = 0; i<16;i++){
			printf("%x ",autn[i]);
		}
		printf("\n");
	printf("\t AK: ");
	for(i = 0; i<6;i++){
		printf("%x",ak[i]);
	}
	printf("\n");
	printf("\t K: ");
	for(i = 0; i<SIZE_K;i++){
		printf("%x",ue_storage[stor_index].key[i]);
	}
	printf("\n");
	printf("\t SQN: ");
	for(i = 0; i<6;i++){
		printf("%x",ue_storage[stor_index].sqn[i]);
	}
	printf("\n");
	printf("\t CK: ");
	for(i = 0; i<16;i++){
		printf("%x",ck[i]);
	}
	printf("\n");
	printf("\t IK: ");
	for(i = 0; i<16;i++){
		printf("%x",ik[i]);
	}
	printf("\n");
	printf("\t RES: ");
	for(i = 0; i<8;i++){
		printf("%x",res[i]);
	}
	printf("\n");
#endif
#ifdef measurefct
	b=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",a);
	printf("B: %lu \n",b);
	printf("generate_Autn Duration %lu ns\n",b-a);
#endif
	return;
}

void derive_Kausf(sn_name_t sn_name, int stor_index, uint8_t rand[16],uint8_t kausf[32]){

#ifdef showmethod
	printm(ebene,"UDM: derive_Kausf\n");
#endif
#ifdef measurefct
	uint64_t a,b;
	a=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef DebugAkmaInfo
	printf("\nUDM print key: ");
	for(int i=0;i<sizeof(ue_storage[stor_index].key);i++){
		printf("%02x",ue_storage[stor_index].key[i]);
	}
	printf("\n");

	printf("\nUDM print rand: ");
	for(int i=0;i<16;i++){
		printf("%02x",rand[i]);
	}
	printf("\n");
#endif
	// K_ausf derivation function (TS33.501, Annex A.2)
	uint8_t ak[6];
	uint8_t res[8], ck[16], ik[16];
	f2345(ue_storage[stor_index].key, rand, res, ck, ik, ak);

#ifdef DebugAkmaInfo
	printf("\nUDM print res: ");
	for(int i=0;i<sizeof(res);i++){
		printf("%02x",res[i]);
	}
	printf("\n");
	printf("\nUDM print ck: ");
	for(int i=0;i<sizeof(ck);i++){
		printf("%02x",ck[i]);
	}
	printf("\n");
	printf("\nUDM print ik: ");
	for(int i=0;i<sizeof(ik);i++){
		printf("%02x",ik[i]);
	}
	printf("\n");
	printf("\nUDM print ak: ");
	for(int i=0;i<sizeof(ak);i++){
		printf("%02x",ak[i]);
	}
	printf("\n");

	printf("\nUDM print sn_name: ");
	printf("%s\n",sn_name);
	for(int i=0;i<SIZE_SN_NAME;i++){
		printf("%02x",sn_name[i]);
	}
	printf("\n");

	printf("\nUDM print ue_storage[stor_index].sqn: ");
	for(int i=0;i<sizeof(ue_storage[stor_index].sqn);i++){
		printf("%02x",ue_storage[stor_index].sqn[i]);
	}
	printf("\n");
#endif

	uint8_t fc = 0x6a;
	char pn[SIZE_SN_NAME + 6];
	uint16_t ln[2];
	for(int i=0; i<SIZE_SN_NAME;i++){
		pn[i] = sn_name[i];
	}
	ln[0] = SIZE_SN_NAME;
	for(int i = 0; i<6;i++){
		pn[ln[0]+i] = ue_storage[stor_index].sqn[i] ^ ak[i];
	} 	// SQN XOR AK
	ln[1] = 6; // Length of SQN XOR AK

#ifdef DebugAkmaInfo
	printf("\nUDM print ln: ");
	for(int i=0;i<sizeof(ln);i++){
		printf("%02x",ln[i]);
	}
	printf("\n");

	printf("\nUDM print ue_storage[stor_index].key(%d): ", SIZE_K);
	for(int i=0;i<sizeof(ue_storage[stor_index].key);i++){
		printf("%02x",ue_storage[stor_index].key[i]);
	}
	printf("\n");
	printf("\nUDM print fc: ");
	for(int i=0;i<sizeof(fc);i++){
		printf("%02x",fc);
	}
	printf("\n");
	printf("\nUDM print pn: ");
	for(int i=0;i<sizeof(pn);i++){
		printf("%02x",pn[i]);
	}
	printf("\n");
	printf("\nUDM print ln: ");
	for(int i=0;i<sizeof(ln);i++){
		printf("%02x",ln[i]);
	}
	printf("\n");
#endif

	genericKeyDerivation(ue_storage[stor_index].key,SIZE_K,fc,(uint8_t*)pn,ln,2,kausf);

#ifdef measurefct
	b=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",a);
	printf("B: %lu \n",b);
	printf("derive_Kausf Duration %lu ns\n",b-a);
#endif
	return;
}

static void calc_XRESstar(uint8_t XRESstar[32], sn_name_t sn_name, int stor_index, uint8_t rand[16]){
#ifdef showmethod
	printm(ebene,"UDM: calc_XRESstar\n");
#endif
#ifdef measurefct
	uint64_t a,b;
	a=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	// RES* and XRES* derivation function (TS33.501, Annex A.4)
	int n = 3, rand_size=16, res_size=8;
	uint8_t ak[6],res[8], ck[16], ik[16];
	f2345(ue_storage[stor_index].key, rand, res, ck, ik, ak);


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
#ifdef testb
	printf("UDM: RES_star\n");
	printf("\t res_star: ");
	for(int i = 0; i<32;i++){
		printf("%x",XRESstar[i]);
	}
	printf("\n");
#endif

#ifdef measurefct
	b=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",a);
	printf("B: %lu \n",b);
	printf("calc_XRESstar Duration %lu ns\n",b-a);
#endif
	return;
}

void udm_init(){
#ifdef showmethod
	printm(ebene,"UDM: initUDM\n");
#endif
	initUEStorage();
	sidf_init();
}

void udm_close(){

}


static void deconcealSUCI(supi_t* supi, suci_t* suci){
#ifdef showmethod
	printm(ebene,"UDM: deconcealSUCI\n");
#endif
#ifdef measurefct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	size_t secretlen, keylen=128;
	unsigned char* sharedSecret;
	unsigned char key[128],supi_tmp[128];
	unsigned char publicKey[65];
#ifdef testb
	puts("SUCI.msin");
	for(int i=0; i<sizeof(suci->msin);i++){
		printf("%x", suci->msin[i]);
	}
	puts("\n");
#endif
#ifdef testb
	puts("SUCI.eccpubkey");
#endif
	for(int i=0; i<sizeof(suci->ecc_pub_key);i++){
#ifdef testb
		printf("%x", suci->ecc_pub_key[i]);
#endif
		publicKey[i] = (unsigned char)suci->ecc_pub_key[i];
	}
#ifdef testb
	puts("\n");
#endif
	// TODO: generated key not used, instead fixed sharedsecret
	printf("UDM print publicKey:");
	for(int i=0; i< 65;i++){
		printf("%02x", publicKey[i]);
	}
	printf("\n");
#ifdef measureAKMAfct
	uint64_t y1,z1;
	y1=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	sharedSecret = getSharedSecret(&secretlen, &publicKey, 65); // TODO: get right shared secret
#ifdef measureAKMAfct
	z1=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	printf("UDM getSharedSecret Duration %lu ns\n",z1-y1);
#endif
	printf("UDM print sharedSecret:");
	for(int i=0; i< secretlen;i++){
		printf("%02x", sharedSecret[i]);
	}
	printf("\n");
#ifdef testb
	puts("shared:");
	for(int i=0; i<secretlen;i++){
			printf("%X",sharedSecret[i]);
		}
	puts("");
#endif

	for(int i=0; i<sizeof(suci->mcc_mnc);i++){
		(supi->mcc_mnc)[i]= (uint8_t)(suci->mcc_mnc)[i];
	}
	kdf(sharedSecret, secretlen, &keylen, NULL, 0, &key);	


	int a = decrypt(suci->msin, sizeof(suci->msin),key, 0, supi_tmp);

	for(int i=0; i<sizeof(supi->msin);i++){
//		printf("%x",suci_tmp[i]);
		supi->msin[i]= (uint8_t)supi_tmp[i];
	}
	printf("\n==========supi->mcc_mnc================\n");
	for(int i =0;i<sizeof(supi->mcc_mnc);i++) {
		printf("%02x", supi->mcc_mnc[i]);
	}
	printf("\n==========supi->mnc================\n");
	printf("\n==========supi->msin================\n");
	for(int i =0;i<sizeof(supi->msin);i++) {
		printf("%02x", supi->msin[i]);
	}
	printf("\n==========supi->msin================\n");

#ifdef testb
	printf("SUCI.msin: %d\n", a);
	for(int i=0; i<sizeof(suci->msin);i++){
		printf("%x", suci->msin[i]);
	}
	puts("\n");
	printf("SUPI.msin: %d\n", a);
	for(int i=0; i<sizeof(supi->msin);i++){
		printf("%x", supi->msin[i]);
	}
	puts("\n");
#endif

#ifdef measurefct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",y);
	printf("B: %lu \n",z);
	printf("deconcealSuci Duration %lu ns\n",z-y);
#endif
	return;
}

int chooseAuthenticationMethod(int storageindex){
	return ue_storage[storageindex].authMethod;
}

void Nudm_UEAuthenticationRequest(he_av_t* av, suci_t* suci, sn_name_t* sn_name){
#ifdef showmethod
	printm(ebene,"UDM: Nudm_UEAuthenticationRequest Begin\n");
#endif
#ifdef measurefct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	printf("UDM print suci\n");
	printf("\t mcc_mnc:");
	for(int i=0; i< sizeof(suci->mcc_mnc);i++){
		printf("%02x", suci->mcc_mnc[i]);
	}
	printf("\n\t msin:");
	for(int i=0; i< sizeof(suci->msin);i++){
		printf("%02x", suci->msin[i]);
	}
	printf("\n\t msin:");
	for(int i=0; i< sizeof(suci->ecc_pub_key);i++){
		printf("%02x", suci->ecc_pub_key[i]);
	}
	printf("\n");

#ifdef measure
	printf("Tin: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif
	// Important delay.
	// for(int i=0; i<sizeof(suci->ecc_pub_key);i++){
		//		printf("%x", suci->ecc_pub_key[i]);
	// }
#ifdef testb
	//printf("SUCI.msin");
	//	for(int i=0; i<sizeof(suci->msin);i++){
	//		printf("%x", suci->msin[i]);
	//	}
	//	puts("\n");
	//	puts("SUCI.eccpubkey");
		for(int i=0; i<sizeof(suci->ecc_pub_key);i++){
	//		printf("%x", suci->ecc_pub_key[i]);
		}
	//	puts("\n");
#endif
	// SUCI de-concealment
#ifdef testb
	printf("UDM: SUCI deconcealment\n");
#endif
	supi_t supi;
	deconcealSUCI(&supi, suci);
	// Authentication Method selection
#ifdef testb
	printf("UDM: select authentication method\n");
#endif
	int method;
	int stor_index = getIndex(supi);
	method = chooseAuthenticationMethod(stor_index);
#ifdef test
	printf("UDM: authentication method: %d\n",method);
#endif
	// Create authentication vector
#ifdef test
	printf("UDM: create authentication vector\n");
#endif
	//he_av_t HE_AV_5G;
	av->method = method;
	for(int idx=0; idx< sizeof(av->rand);idx++){
		av->rand[idx] = rand();
	}


	generate_Autn(stor_index,av->rand, av->autn);
	derive_Kausf(sn_name, stor_index, av->rand, av->k_ausf);

	printf("\nUDM print av->k_ausf: ");
	for(int i=0;i<sizeof(av->k_ausf);i++){
		printf("%02x",av->k_ausf[i]);
	}
	printf("\n");

	calc_XRESstar(av->xres_star, sn_name, stor_index, av->rand );
	for(int idx=0; idx< sizeof(supi.mcc_mnc);idx++){
		av->supi.mcc_mnc[idx] = supi.mcc_mnc[idx];
	}
	for(int idx=0; idx< sizeof(supi.msin);idx++){
		av->supi.msin[idx] = supi.msin[idx];
	}

	/* akma add begin
	*/
	memset(&g_he_av, 0x00, sizeof(he_av_t));
	memcpy(&g_he_av, av, sizeof(he_av_t));
	/* akma add end
	*/
#ifdef test
	printf("UDM: authentication vector\n");
	printf("\t method: %d", method);
	printf("\n");
	printf("\t rand: ");
	for(int i=0; i<16; i++){
		printf("%x",av->rand[i]);
	}
	printf("\n");
	printf("\t autn: ");
	for(int i=0; i<16; i++){
		printf("%x",av->autn[i]);
	}
	printf("\n");
	printf("\t xres_star: ");
	for(int i=0; i<32; i++){
		printf("%x",av->xres_star[i]);
	}
	printf("\n");
	printf("\t k_ausf: ");
	for(int i=0; i<32; i++){
		printf("%x",av->k_ausf[i]);
	}
	printf("\n");
	printf("\t supi: ");
	for(int i=0; i<8; i++){
		if(i<3){
			printf("%x", av->supi.mcc_mnc[i]);
		} else {
			printf("%x", av->supi.msin[i-3]);
		}
	}
	printf("\n");
#endif
#ifdef measure
	printf("Tout: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
#endif

#ifdef measurefct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",y);
	printf("B: %lu \n",z);
	printf("Nudm_AuthenticationRequest Duration %lu ns\n",z-y);
#endif
#ifdef showmethod
	printm(ebene,"UDM: Nudm_UEAuthenticationRequest End\n");
#endif
	printf("OK    BNudm_UEAuthenticationRequest\n");
	return;
}

void Nudm_AuthenticationSuccessful(supi_t supi, struct timeval timestamp, int authType, sn_name_t sn_name){
#ifdef	showmethod
	printm(ebene,"UDM: Nudm_AuthenticationSuccessful\n");
#endif
#ifdef measurefct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	printf("\tSUPI: ");
	for(int i=0; i<sizeof(supi.mcc_mnc);i++){
		printf("%x", supi.mcc_mnc[i]);
	}
	for(int i=0; i<sizeof(supi.msin);i++){
		printf("%x", supi.msin[i]);
	}
	printf("\n");
	if(authType==1){
		printf("\tAuthType: EAP-AKA'\n");
	}else if(authType==2){
		printf("\tAuthType: 5G-AKA'\n");
	}
	printf("\tSN-Name: ");
	for(int i=0; i<10;i++){
		printf("%c", sn_name[i]);
	}
	printf("\n");
	printf("\tTimestamp: %d\n", timestamp.tv_sec);

#ifdef measurefct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",y);
	printf("B: %lu \n",z);
	printf("Nudm_AuthenticationSuccessful Duration %lu ns\n",z-y);
#endif
}


// AKMA
/*
supi_t * supi: input
suci_t * suci: input 
he_av_t * he_av: output
uint8_t *AKMA_Ind: output 
rid_t *rid: output
*/
void Nudm_UEAuthentication_Get_Request_UDM(supi_t * supi, suci_t *suci, he_av_t * he_av, uint8_t *AKMA_Ind, rid_t *rid){
#ifdef showAKMAmethod 
    printf("AKMA step 1 (AUSF-->UDM) Nudm_UEAuthentication_Get_Request_UDM(supi, suci) Receive \n");
#endif

#ifdef CommCosts 
	int costLen = sizeof(supi_t) + sizeof(suci_t);
	printf("\nAKMA step 1 (AUSF-->UDM) UDM receive message from AUSF (%d bytes)\n", costLen);
#endif

	/*
	udm has got rid during 5G-AKA, here is a simple way to initialte.
	*/
	for(int i=0;i<4;i++) {
		rid->rid[i] =i+1;
	}

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("UDM step 1 Duration %lu ns\n",z-y);
#endif

	Nudm_UEAuthentication_Get_Response_UDM(supi,rid, he_av, AKMA_Ind);



#ifdef DebugAkmaInfo
	printf("\n");
	printf("\t Nudm_UEAuthentication_Get_Request_UDM supi: ");
	for(int i=0; i<8; i++){
		if(i<3){
			printf("%x", he_av->supi.mcc_mnc[i]);
		} else {
			printf("%x", he_av->supi.msin[i-3]);
		}
	}
	printf("\n");
#endif

#ifdef measureAKMAfct
	uint64_t y0,z0;
	y0=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
    // step 3 generate A-KID from k_ausf, supi

	if(udm_akid_pair_index + udm_akid_pair_size >=udm_akid_pair_max_size) {
		fprintf(stderr, "not enough space store udm_akid_pair_t in udm_akid_pair_db\n");
		fprintf(stderr, "udm_akid_pair_index = %d, udm_akid_pair_max_size=%d, udm_akid_pair_size=%d\n", 
			udm_akid_pair_index,
			udm_akid_pair_max_size, 
			udm_akid_pair_size
			);
        exit(1);
	}

	unsigned char currentDate[9];
	getCurrentDate(currentDate);

	for (int i = 0; i < udm_akid_pair_size; i++)
	{
		UDM_calc_AKID_from_KAUSF_2(he_av->k_ausf, supi, rid, i, currentDate, &(udm_akid_pair[i].a_kid));
		memcpy(udm_akid_pair[i].supi.mcc_mnc, supi->mcc_mnc, sizeof(supi->mcc_mnc));
		memcpy(udm_akid_pair[i].supi.msin, supi->msin, sizeof(supi->msin));
		udm_akid_pair_db[udm_akid_pair_index + i] = udm_akid_pair[i];
	}

	udm_akid_pair_index += udm_akid_pair_size;

#ifdef measureAKMAfct
	z0=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	printf("UDM step 3 Duration %lu ns (it can be ignored due to UE,AUSF run it at the same time.)\n",z0-y0);
#endif

}

/*
supi: input
rid: input, output
he_av: output
AKMA_Ind: output

*/
void Nudm_UEAuthentication_Get_Response_UDM(supi_t * supi, rid_t *rid , he_av_t * he_av, uint8_t *AKMA_Ind){
#ifdef showAKMAmethod
    printf("AKMA step 2 (UDM-->AUSF) Nudm_UEAuthentication_Get_Response_UDM(supi, rid, he_av, AKMA_Ind) send \n");
#endif

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	memcpy(he_av, &g_he_av, sizeof(he_av_t));
	*AKMA_Ind = 0;// whether UDM needs to generate the K_AKMA for UE. 1-yes, 0-no

#ifdef DebugAkmaInfo
	printf("\tUDM: authentication vector (AV)\n");
	printf("\t method: %d", he_av->method);
	printf("\n");
	printf("\t rand: ");
	for(int i=0; i<16; i++){
		printf("%x",he_av->rand[i]);
	}
	printf("\n");
	printf("\t autn: ");
	for(int i=0; i<16; i++){
		printf("%x",he_av->autn[i]);
	}
	printf("\n");
	printf("\t xres_star: ");
	for(int i=0; i<32; i++){
		printf("%x",he_av->xres_star[i]);
	}
	printf("\n");
	printf("\t k_ausf: ");
	for(int i=0; i<32; i++){
		printf("%x",he_av->k_ausf[i]);
	}
	printf("\n");
	printf("\t supi: ");
	for(int i=0; i<8; i++){
		if(i<3){
			printf("%x", he_av->supi.mcc_mnc[i]);
		} else {
			printf("%x", he_av->supi.msin[i-3]);
		}
	}
	printf("\n");

	printf("\tUDM: AKMA Ind: %d (UDM does not need to generate the K_AKMA for UE)\n", *AKMA_Ind);


	printf("\tUDM: Routing Indicator (RID): ");
	for(int i=0; i<4; i++){
		printf("%x",rid->rid[i]);
	}
	printf("\n");
#endif


#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("UDM step 2 Duration %lu ns\n",z-y);
#endif

#ifdef CommCosts 
	int costLen = sizeof(he_av_t) + sizeof(uint8_t) + sizeof(rid_t);
	printf("\nAKMA step 2 (UDM-->AUSF) UDM send message to AUSF (%d bytes)\n", costLen);
#endif

}

/*
supi_t * supi: input
gpsi_t * gpsi: output
*/
void Nudm_SDM_GetRequest_UDM(supi_t * supi, gpsi_t * gpsi){
#ifdef showAKMAmethod
    printf("AKMA step 8 (AAnF-->UDM) Nudm_SDM_GetRequest_UDM(supi_t) receive \n");
#endif

#ifdef CommCosts 
	int costLen = sizeof(supi_t);
	printf("\nAKMA step 8 (AAnF-->UDM) UDM receive message from AAnF (%d bytes)\n", costLen);
#endif

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("UDM step 8 Duration %lu ns\n",z-y);
#endif

	Nudm_SDM_GetResponse_UDM(&gpsi);

}

void Nudm_SDM_GetResponse_UDM(gpsi_t * gpsi){
#ifdef showAKMAmethod
    printf("AKMA step 9 (UDM-->AAnF) Nudm_SDM_GetResponse_UDM(gpsi_t) send \n");
#endif

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	// generate gpsi
	memset(gpsi->gpsi, 0x00, sizeof(gpsi->gpsi));

#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("UDM step 9 Duration %lu ns\n",z-y);
#endif

#ifdef CommCosts 
	int costLen = sizeof(gpsi_t);
	printf("\nAKMA step 9 (UDM-->AAnF) UDM send message to AAnF (%d bytes)\n", costLen);
#endif
}

/*
a_kid_t * a_kid: input
unsigned char *roaming: output
unsigned char *New_servingPlmn: output
unsigned char *accessType: output
*/
void Nudm_EventExposure_Subscribe_Request_UDM(a_kid_t * a_kid, 
	unsigned char *roaming, unsigned char *New_servingPlmn, unsigned char *accessType){
#ifdef showAKMAmethod
    printf("AKMA step 10 (AAnF-->UDM) Nudm_EventExposure_Subscribe_Request_UDM(a_kid_t, roaming, New_servingPlmn, accessType) receive \n");
#endif

#ifdef CommCosts 
	int costLen = sizeof(a_kid_t);
	printf("\nAKMA step 10 (AAnF-->UDM) UDM receive message from AAnF (%d bytes)\n", costLen);
#endif

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("UDM step 10 Duration %lu ns\n",z-y);
#endif
#ifdef DebugAkmaInfo
	printf("Nudm_EventExposure_Subscribe_Request_UDM input a_kid\n");
	print_akid(a_kid);
#endif
	/*
	step 11
	*/
	Nudm_EventExposure_Subscribe_Response_UDM(a_kid, roaming, New_servingPlmn, accessType);

}

void Nudm_EventExposure_Subscribe_Response_UDM(a_kid_t * a_kid, 
	unsigned char *roaming, unsigned char *New_servingPlmn, unsigned char *accessType){
#ifdef showAKMAmethod
    printf("AKMA step 11 (UDM-->AAnF) Nudm_EventExposure_Subscribe_Response_UDM(a_kid_t, roaming, New_servingPlmn, accessType) send \n");
#endif

#ifdef measureAKMAfct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	supi_t supi;
	// get supi, roaming,New_servingPlmn,accessType
#ifdef DebugAkmaInfo
	printf("Nudm_EventExposure_Subscribe_Response_UDM input a_kid\n");
	print_akid(a_kid);
#endif
	int index = UDM_Get_SUPI(a_kid, &supi);
	if(index < 0) {
		fprintf(stderr, "get supi from udm_akid_pair_db error\n");
		exit(1);
	}
	memcpy(roaming, "roaming", strlen("roaming"));
	memcpy(New_servingPlmn, "New_servingPlmn", strlen("New_servingPlmn"));
	memcpy(accessType, "accessType", strlen("accessType"));
	

#ifdef measureAKMAfct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("A: %lu \n",y);
	// printf("B: %lu \n",z);
	printf("UDM step 11 Duration %lu ns\n",z-y);
#endif

#ifdef CommCosts 
	int costLen = strlen(roaming) + strlen(New_servingPlmn) + strlen(accessType);
	printf("\nAKMA Step 11 (UDM-->AAnF) UDM send message to AAnF (%d bytes)\n", costLen);
#endif
}


/*
k_ausf:input
supi:input
counter:input
date:input
a_kid:output
*/
void UDM_calc_AKID_from_KAUSF_2(k_ausf_t *k_ausf, supi_t *supi, rid_t *rid,
		int counter, unsigned char *date, a_kid_t *a_kid){
#ifdef showAKMAmethod
    printf("AKMA step 3(UDM calc) UDM_calc_AKID_from_KAUSF_2(k_ausf,supi,a_kid) begin \n");
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

	memcpy((a_kid->username).a_tid, a_tid, sizeof(a_tid));
	memcpy(&(a_kid->username).rid, rid, sizeof(rid_t));
	memcpy(a_kid->at, "@", 1);
	memset(a_kid->realm, 0xFF, sizeof(a_kid->realm));
#ifdef measureAKMAfct2
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	printf("UDM step 3 UDM_calc_AKID_from_KAUSF_2 Duration %lu ns\n",z-y);
#endif
#ifdef DebugAkmaInfo
	print_akid(a_kid);
#endif

}


/*
a_kid_t * a_kid input
supi_t * p_supi output
return value:
-1 not found
others index
*/

int UDM_Get_SUPI(a_kid_t * a_kid, supi_t * p_supi)
{
#ifdef DebugAkmaInfo
	printf("*************UDM_Get_SUPI start*************, udm_akid_pair_index = %d\n", udm_akid_pair_index);
#endif
#ifdef DebugAkmaInfo
	printf("UDM_Get_SUPI input a_kid\n");
	print_akid(a_kid);
#endif
	// (a_kid->username).a_tid;
	// (akma_pair_db[i]).a_kid.username.a_tid
	for (int i=0;i<udm_akid_pair_index;i++) {
#ifdef DebugAkmaInfo
		printf("i=%d, (udm_akid_pair_db[i]).a_kid.username.a_tid= ", i);
		for(int j=0;j<sizeof((udm_akid_pair_db[i]).a_kid.username.a_tid);j++) {
			printf("%02x", ((udm_akid_pair_db[i]).a_kid.username.a_tid)[j]);
		}
		printf("\n");
#endif
		if(strncmp((a_kid->username).a_tid, 
			(udm_akid_pair_db[i]).a_kid.username.a_tid, 
			sizeof((a_kid->username).a_tid)) == 0)
		{
			(*p_supi) =  (udm_akid_pair_db[i]).supi;
			return i;
		}
	}
	return -1;

}