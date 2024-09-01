/*
 * UDM.h
 *
 */

#ifndef UDM_H_
#define UDM_H_

#include "identifier.h"
#include "av_types.h"
#include "defs.h"


void udm_init();
void udm_close();
void Nudm_UEAuthenticationRequest(he_av_t* av, suci_t* suci, sn_name_t* sn_name);
void Nudm_AuthenticationSuccessful();
void Nudm_UEAuthentication_Get_Request_UDM(supi_t * supi, suci_t *suci, he_av_t * he_av, uint8_t *AKMA_Ind, rid_t *rid);
void Nudm_SDM_GetRequest_UDM(supi_t * supi, gpsi_t * gpsi);
void Nudm_SDM_GetResponse_UDM(gpsi_t * gpsi);
void Nudm_EventExposure_Subscribe_Request_UDM(a_kid_t * a_kid, 
	unsigned char *roaming, unsigned char *New_servingPlmn, unsigned char *accessType);
void Nudm_EventExposure_Subscribe_Response_UDM(a_kid_t * a_kid, 
	unsigned char *roaming, unsigned char *New_servingPlmn, unsigned char *accessType);

#endif /* UDM_H_ */
