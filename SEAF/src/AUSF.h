/*
 * AUSF.h
 *
 */

// Includes
#include <stdlib.h>
#include "identifier.h"
#include "av_types.h"
#include "defs.h"

#ifndef AUSF_H_
#define AUSF_H_
// Authenticate request
void ausf_init();
void ausf_close();
void Nausf_UEAuthenticationRequest(se_av_t* se_av, suci_t* suci, sn_name_t* sn_name);
int Nausf_UEAuthenticationResponse(uint8_t* res, supi_t *supi, uint8_t *kseaf);
void Nudm_UEAuthentication_Get_Request_AUSF(supi_t * supi, suci_t *suci);

static void calc_KAKMA_from_KAUSF(k_ausf_t *k_ausf, supi_t *supi, k_akma_t *k_akma);
static void calc_AKID_from_KAUSF(k_ausf_t *k_ausf, supi_t *supi, a_kid_t *a_kid);
void Nudm_UEAuthentication_Get_Response_AUSF(he_av_t * he_av, uint8_t AKMA_Ind, rid_t *rid);
void Naanf_AKMA_AnchorKey_Register_Request_AUSF_2(akma_pair_t * p_akma_pair, size_t akma_pair_size);
void calc_AKID_from_KAUSF_2(k_ausf_t *k_ausf, supi_t *supi, 
		int counter, unsigned char *date, a_kid_t *a_kid);
void Naanf_AKMA_AnchorKey_Register_Request_AUSF_2(akma_pair_t * p_akma_pair, size_t akma_pair_size);
#endif /* AUSF_H_ */
