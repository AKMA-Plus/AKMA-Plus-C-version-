/*
 * AAnF.h
 */

// Includes
#include <stdlib.h>
#include "identifier.h"
#include "av_types.h"
#include "defs.h"



#ifndef AAnF_H_
#define AAnF_H_
// Authenticate request
void aanf_init();
static void calc_KAF_from_KAKMA(k_akma_t *k_akma, af_id_t *af_id, k_af_t *k_af);
void Naanf_AKMA_AnchorKey_Register_Request_AAnF(supi_t * supi, a_kid_t * a_kid, k_akma_t * k_akma);
void Naanf_AKMA_ApplicationKey_GetRequest_AAnF(a_kid_t * a_kid, af_id_t * af_id, 
		unsigned char *enc_CT_AAnF, size_t enc_CT_AAnF_len, unsigned char *CT_AAnF_TAG,
		unsigned char *buf, int *plen);
void Naanf_AKMA_ApplicationKey_GetResonse_AAnF(k_af_t *k_af, struct timeval *k_af_exp, supi_t * supi, 
    unsigned char *Res_AAnF, int Res_AAnF_len, 
    unsigned char *Res_AAnF_sign, int Res_AAnF_sign_len, 
    unsigned char *buf, int *plen);
void Naanf_AKMA_ApplicationKey_GetResonse_AAnF_2(k_af_t *k_af, struct timeval *k_af_exp, supi_t * supi, 
    unsigned char *CT_AAnF_UE, int CT_AAnF_UE_Len, unsigned char *CT_AAnF_UE_TAG, 
    unsigned char *buf, int *plen);
void ResAAnF_Sign(af_id_t *af_id, unsigned char *dec_CT_AAnF, int dec_CT_AAnF_len, 
        unsigned char *Res_AAnF, unsigned int *pRes_AAnF_len,
        unsigned char *Res_AAnF_sign, unsigned int *pRes_AAnF_sign_len);
void Naanf_AKMA_AnchorKey_Register_Request_AAnF_2(akma_pair_t * akma_pair, size_t akma_pair_size);
#endif /* AAnF_H_ */
