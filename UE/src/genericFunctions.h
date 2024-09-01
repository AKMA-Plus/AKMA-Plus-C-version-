/*
 * genericFunctions.h
 *
 */

#ifndef GENERICFUNCTIONS_H_
#define GENERICFUNCTIONS_H_



#endif /* GENERICFUNCTIONS_H_ */

#include "identifier.h"
#include "defs.h"
void genericKeyDerivation(uint8_t *key,uint8_t keysize,uint8_t fc, uint8_t* pn, uint16_t* ln, uint8_t n, uint8_t* output);
void print_akid(a_kid_t * a_kid);
void print_afid(af_id_t * af_id);
int ParseAKID2Buf(a_kid_t * a_kid, unsigned char * msg, int len);
