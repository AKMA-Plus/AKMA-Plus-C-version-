/*
 ============================================================================
 Name        : av_types.h
 ============================================================================
 */

#ifndef AV_TYPES_H_
#define AV_TYPES_H_

#include <stdlib.h>

typedef struct{
	uint8_t method;
	uint8_t rand[16];
	uint8_t autn[16];
	uint8_t hxres_star[32]; 
	uint8_t k_seaf[32];
	supi_t supi;
}av_t;

typedef struct{
	uint8_t rand[16];
	uint8_t autn[16];
	uint8_t hxres_star[32];
}se_av_t;

typedef struct{
	uint8_t method;
	uint8_t rand[16];
	uint8_t autn[16];
	uint8_t xres_star[32];
	uint8_t k_ausf[32];
	supi_t supi;
}he_av_t;

#endif /* AV_TYPES_ */
