/*
 ============================================================================
 Name        : identifier.h
 ============================================================================
 */

#ifndef IDENTIFIER_H_
#define IDENTIFIER_H_

#include <stdlib.h>
#include <stdint.h>

#define SIZE_SUPI_BYTE 7 // Maximum 60 bits
#define SIZE_SUCI_BYTE 7 //
#define SIZE_GUTI_BYTE 7 //
#define SIZE_SN_NAME 1020 // Maximum 1020 octets (TS24.501, 9.11.1)
#define SIZE_K 16 // in Byte. Should be 128 bits (16) or 256 bits (32)

//typedef uint8_t supi_t[SIZE_SUPI_BYTE];
//typedef uint8_t suci_t[SIZE_SUCI_BYTE];
typedef uint8_t guti_5G_t[SIZE_GUTI_BYTE];
typedef char sn_name_t[SIZE_SN_NAME];

typedef struct {
	uint8_t mcc_mnc[3];
	uint8_t msin[5];
	uint8_t ecc_pub_key[65];
} suci_t;

typedef struct {
	uint8_t mcc_mnc[3];
	uint8_t msin[5];
} supi_t;

// structs in AKMA

typedef struct {
	uint8_t rid[4];  //
} rid_t;

typedef struct {
	rid_t rid;  //
	uint8_t a_tid[32]; // kdf output 256 bits
} username_t;

typedef struct {
	username_t username;
	uint8_t at[1];  // "@"
	uint8_t realm[35];
} a_kid_t;

typedef struct {
	uint8_t fqdn[255];
	uint8_t uaid[5];
} af_id_t;

typedef struct {
	uint8_t gpsi[10];
} gpsi_t;

typedef struct {
	uint8_t k_ausf[32]; // kdf output 256 bits
} k_ausf_t;

typedef struct {
	uint8_t k_akma[32]; // kdf output 256 bits
} k_akma_t;

typedef struct {
	uint8_t k_af[32]; // kdf output 256 bits
} k_af_t;

typedef struct {
	k_akma_t k_akma;
	a_kid_t a_kid;
} akma_pair_t;

typedef struct {
	a_kid_t a_kid;
	supi_t supi;
} udm_akid_pair_t;




#endif /* IDENTIFIER_H_ */
