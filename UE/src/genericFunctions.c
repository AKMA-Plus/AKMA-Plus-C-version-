/*
 * genericFunctions.c
 *
 */

#include "genericFunctions.h"
#include "identifier.h"
#include "deps/hmac-sha256/hmac-sha256.h"
#include <time.h>

// TS33.220 Annex B.2
void genericKeyDerivation(uint8_t *key,uint8_t keysize,uint8_t fc, uint8_t *pn, uint16_t *ln, uint8_t n, uint8_t *output)
{
#ifdef showmethod
	printf("\tgenericKeyDerivation (KDF)\n");
#endif
#ifdef measurefct
	uint64_t y,z;
	y=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif
	// printf("\n");
	// printf("UE genericKeyDerivation print output: ");
	// for(int i=0; i<32; i++){
	// 	printf("%02x",output[i]);
	// }
	// printf("\n");
	// uint64_t a,b;
	// a = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// S = FC || P0 || L0 || P1 || L1 || P2 || L2 || P3 || L3 ||... || Pn || Ln
	size_t datalength = 1;
	for (int i = 0; i<n; i++)
	{
		datalength += ln[i];
		datalength += 2;  //store ln, ln is uint16_t, s is uint8_t, so it needs additional two uint8_t
	}
	uint8_t s[datalength];

#ifdef DebugAkmaInfo
	printf("\tdatalength = %d\n", datalength);

	printf("\tFC = 0x%02x\n", fc);
	int plen = 0;
	for (int i = 0; i < n; i++)
	{
		printf("\tP%d = ",i);
		for (int j = 0; j < ln[i]; j++)
		{
			printf("%02x", pn[plen + j]);
		}
		printf("\n\tL%d = %d\n", i, ln[i]);
		plen += ln[i];
	}
#endif

	s[0] = fc;
	int s_start = 1;
	int p_start = 0;
	for(int i = 0; i<n; i++)
	{
		for(int j=0; j<ln[i]; j++)
		{
			s[s_start+j]=pn[p_start+j];
		}
		//ln is uint16_t, s is uint8_t, so it needs to store low 8 bits and high 8 bits
		s[s_start + ln[i]] = ln[i]; 
		s[s_start + ln[i] + 1] = (ln[i] >> 8);
		s_start += (ln[i] + 2);
		p_start += ln[i];
	}

	// printf("\n");
	// printf("UE genericKeyDerivation before hmac_sha256 print output: ");
	// for(int i=0; i<32; i++){
	// 	printf("%02x",output[i]);
	// }
	// printf("\n");

	// printf("\n");
	// printf("UE genericKeyDerivation before hmac_sha256 print s(%d): ", datalength);
	// for(int i=0; i<sizeof(s); i++){
	// 	printf("%02x",s[i]);
	// }
	// printf("\n");
	// printf("\n");
	// printf("UE genericKeyDerivation before hmac_sha256 print key(%d): ", keysize);
	// for(int i=0; i<keysize; i++){
	// 	printf("%02x",key[i]);
	// }
	// printf("\n");


	//derivedKey = HMAC-SHA-256(key,s)
	hmac_sha256(output, s, datalength, key, keysize);//SIZE_K);


	// printf("\n");
	// printf("UE genericKeyDerivation after hmac_sha256 print output: ");
	// for(int i=0; i<32; i++){
	// 	printf("%02x",output[i]);
	// }
	// printf("\n");
	
	// b = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#ifdef measurefct
	z=clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	//printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n",y);
	printf("B: %lu \n",z);
	printf("genericKeyDerivation Duration %lu ns\n",z-y);
#endif
}


void print_akid(a_kid_t * a_kid) {
	printf("\n");
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
}

void print_afid(af_id_t * af_id) {
	printf("\n");
	printf("\t af_id: \n");
	printf("\t\t fqdn: \n");
	for(int i=0; i<sizeof(af_id->fqdn); i++){
		printf("%02x",(af_id->fqdn)[i]);
	}
	printf("\n");
	printf("\t\t uaid: ");
	for(int i=0; i<sizeof(af_id->uaid); i++){
		printf("%02x",(af_id->uaid)[i]);
	}
	printf("\n");
	
}

int ParseAKID2Buf(a_kid_t * a_kid, unsigned char * msg, int len) 
{

	if(len < sizeof(a_kid_t)) {
		perror("Parse2AKID");
		exit(1);
	}

	int offset = 0;

	memcpy(msg + offset, (a_kid->username).rid.rid, sizeof((a_kid->username).rid.rid));
	offset += sizeof((a_kid->username).rid.rid);

	memcpy(msg + offset, (a_kid->username).a_tid, sizeof((a_kid->username).a_tid));
	offset += sizeof((a_kid->username).a_tid);

	memcpy(msg + offset, a_kid->at, sizeof(a_kid->at));
	offset += sizeof(a_kid->at);

	memcpy(msg + offset, a_kid->realm, sizeof(a_kid->realm));
	offset += sizeof(a_kid->realm);

	return offset;

}


