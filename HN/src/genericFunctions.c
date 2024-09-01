/*
 * genericFunctions.c
 *
 */

#include "genericFunctions.h"
#include "identifier.h"
#include "deps/hmac-sha256/hmac-sha256.h"
#include <time.h>
#include <stdio.h>
#include "ffunction.h"

void Parse2AKID(unsigned char * msg, int len, a_kid_t * a_kid);
void Parse2AFID(unsigned char * msg, int len, af_id_t * af_id);


/*
uint8_t *key : input
uint8_t keysize : input
uint8_t fc : input
uint8_t *pn : input
uint16_t *ln : input
uint8_t n : input
uint8_t *output : output(uint8_t [32])
*/
// TS33.220 Annex B.2
void genericKeyDerivation(uint8_t *key, uint8_t keysize, uint8_t fc, uint8_t *pn, uint16_t *ln, uint8_t n, uint8_t *output)
{
#ifdef showmethod
	printf("\tgenericKeyDerivation (KDF)\n");
#endif
#ifdef measurefct
	uint64_t a, b;
	a = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
#endif

	// printf("AUSF genericKeyDerivation print output address 1 %p\n",output);

	// printf("\n");
	// printf("AUSF genericKeyDerivation print output 1: ");
	// for (int i = 0; i < 32; i++)
	// {
	// 	printf("%02x", output[i]);
	// }
	// printf("\n");

	// S = FC || P0 || L0 || P1 || L1 || P2 || L2 || P3 || L3 ||... || Pn || Ln
	size_t datalength = 1;
	for (int i = 0; i < n; i++)
	{
		datalength += ln[i];
		datalength += 2; //store ln, ln is uint16_t, s is uint8_t, so it needs additional two uint8_t
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

	// printf("\n");
	// printf("AUSF genericKeyDerivation print output 2: ");
	// for (int i = 0; i < 32; i++)
	// {
	// 	printf("%02x", output[i]);
	// }
	// printf("\n");

	s[0] = fc;
	int s_start = 1;
	int p_start = 0;
	for (int i = 0; i < n; i++)
	{
		for (int j = 0; j < ln[i]; j++)
		{
			s[s_start + j] = pn[p_start + j];
		}
		//ln is uint16_t, s is uint8_t, so it needs to store low 8 bits and high 8 bits
		s[s_start + ln[i]] = ln[i]; 
		s[s_start + ln[i] + 1] = (ln[i] >> 8);
		s_start += (ln[i] + 2);
		p_start += ln[i];

		// printf("\n");
		// printf("AUSF genericKeyDerivation print output i%d 11: ", i);
		// for (int i = 0; i < 32; i++)
		// {
		// 	printf("%02x", output[i]);
		// }
		// printf("\n");
		// printf("start = %d, ln[%d]=%d, start + ln[i] + 1 = %d, s[start + ln[i] + 1] = %02x, ln[%d]>>8=%02x",
		// 	start, i, ln[i], start + ln[i] + 1, s[start + ln[i] + 1], i, (ln[i] >> 8));

		// printf("AUSF genericKeyDerivation print output address i%d %p\n",i, output);

		// s[start + ln[i] + 1] = (ln[i] >> 8); //overflow here

		// printf("\n");
		// printf("AUSF genericKeyDerivation print output i%d 22: ", i);
		// for (int i = 0; i < 32; i++)
		// {
		// 	printf("%02x", output[i]);
		// }
		// printf("\n");

		// start += ln[i] + 2;  //too long, why plus 2?
	}
	// printf("AUSF genericKeyDerivation print output address 2 %p\n",output);
	// printf("\n");
	// printf("AUSF genericKeyDerivation before hmac_sha256 print output: ");
	// for (int i = 0; i < 32; i++)
	// {
	// 	printf("%02x", output[i]);
	// }
	// printf("\n");

	// printf("\n");
	// printf("UDM genericKeyDerivation before hmac_sha256 print s(%d): ", datalength);
	// for (int i = 0; i < sizeof(s); i++)
	// {
	// 	printf("%02x", s[i]);
	// }
	// printf("\n");
	// printf("\n");
	// printf("UDM genericKeyDerivation before hmac_sha256 print key(%d): ", keysize);
	// for (int i = 0; i < keysize; i++)
	// {
	// 	printf("%02x", key[i]);
	// }
	// printf("\n");

	// derivedKey = HMAC-SHA-256(key,s)
	hmac_sha256(output, s, datalength, key, keysize); // SIZE_K);

	// printf("\n");
	// printf("AUSF genericKeyDerivation after hmac_sha256 print output: ");
	// for (int i = 0; i < 32; i++)
	// {
	// 	printf("%02x", output[i]);
	// }
	// printf("\n");

#ifdef measurefct
	b = clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID);
	// printf("T: %lu \n",clock_gettime_nsec_np_1(CLOCK_PROCESS_CPUTIME_ID));
	printf("A: %lu \n", a);
	printf("B: %lu \n", b);
	printf("genericKeyDerivation Duration %lu ns\n", b - a);
#endif
}

void printm(int numberoftabs, char *s)
{
	for (int i = 0; i < numberoftabs; i++)
	{
		printf("\t");
	}
	printf(s);
	printf("\n");
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
	for(int i=0; i<sizeof((a_kid->username).a_tid); i++){
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


void Parse2AKID(unsigned char * msg, int len, a_kid_t * a_kid){

    // printf("\nParse2AKID get MSG:");
	// for(int i=0; i< len;i++){
	// 	printf("%02x", msg[i]);
	// }
	// printf("\n");

    

	if(len < sizeof(a_kid_t)) {
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

void Parse2AFID(unsigned char * msg, int len, af_id_t * af_id){

	// printf("\nParse2AFID get MSG:");
	// for(int i=0; i< len;i++){
	// 	printf("%02x", msg[i]);
	// }
	// printf("\n");
 
	if(len < sizeof(af_id_t)) {
        perror("Parse2AFID");
		exit(1);
    }

	int offset = 0;

	memcpy(af_id->fqdn, msg + offset, sizeof(af_id->fqdn));
	offset += sizeof(af_id->fqdn);

	memcpy(af_id->uaid, msg + offset, sizeof(af_id->uaid));
	offset += sizeof(af_id->uaid);
	
#ifdef DebugAkmaInfo
    print_afid(af_id);
#endif
}

void getCurrentDate(unsigned *date)
{
	struct timeval tv;
	struct tm *t;

	gettimeofday(&tv, NULL);
	t = localtime(&tv.tv_sec);
	sprintf(date, "%04d%02d%02d", 1900 + t->tm_year, 1 + t->tm_mon, t->tm_mday);
}

