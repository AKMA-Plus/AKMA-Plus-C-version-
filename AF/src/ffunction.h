/*
 * ffunction.h
 *
 */

#ifndef FFUNCTION_H_
#define FFUNCTION_H_

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>

#include "defs.h"

#endif /* FFUNCTION_H_ */
#define NSEC_PER_SEC 1000000000l
#define timeval2nsec(tv) (tv.tv_sec * NSEC_PER_SEC + tv.tv_nsec)

typedef unsigned char u8;

void f1 ( u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2], u8 mac_a[8]);
void f2345 ( u8 k[16], u8 rand[16], u8 res[8], u8 ck[16], u8 ik[16], u8 ak[6] );
void f1star( u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2], u8 mac_s[8] );
void f5star( u8 k[16], u8 rand[16], u8 ak[6] );
uint64_t clock_gettime_nsec_np_1(int clock_id);