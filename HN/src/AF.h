/*
 * AF.h
 *
 */

// Includes
#include <stdlib.h>
#include "identifier.h"
#include "av_types.h"
#include "defs.h"
#include "ffunction.h"

#ifndef AF_H_
#define AF_H_
// Authenticate request

void Naanf_AKMA_ApplicationKey_GetRequest_AF(a_kid_t *a_kid, af_id_t *af_id, 
    unsigned char *enc_CT_UE_AAnF, size_t enc_CT_UE_AAnF_len, unsigned char *CT_UE_AAnF_TAG,
    unsigned char *CT_AAnF_UE, unsigned int *p_CT_AAnF_UE_Len, unsigned char *CT_AAnF_UE_TAG);
void Application_Session_Establishment_Response_AF();

#endif /* AF_H_ */
