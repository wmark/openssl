/******************************************************************************
 *                                                                            *
 * Copyright (c) 2013, Intel Corporation                                      *  
 *                                                                            *
 * All rights reserved.                                                       *
 *                                                                            *
 * Redistribution and use in source and binary forms, with or without         *
 * modification, are permitted provided that the following conditions are     *
 * met:                                                                       *
 *                                                                            *
 *  * Redistributions of source code must retain the above copyright          *
 *    notice, this list of conditions and the following disclaimer.           *
 *                                                                            *
 *  * Redistributions in binary form must reproduce the above copyright       *
 *    notice, this list of conditions and the following disclaimer in the     *
 *    documentation and/or other materials provided with the                  *
 *    distribution.                                                           *
 *                                                                            *
 *  * Neither the name of the Intel Corporation nor the names of its          *
 *    contributors may be used to endorse or promote products derived from    *
 *    this software without specific prior written permission.                *
 *                                                                            *
 *                                                                            *
 * THIS SOFTWARE IS PROVIDED BY INTEL CORPORATION ""AS IS"" AND ANY           *
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE          *
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR         *
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL CORPORATION OR             *
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,      *
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,        *
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR         *
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF     *
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING       *
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS         *
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.               *
 *                                                                            *
 ******************************************************************************
 *                                                                            *
 * Developers and authors:                                                    *
 * Shay Gueron (1, 2), and Vlad Krasnov (1)                                   *
 * (1) Intel Corporation, Israel Development Center                           *
 * (2) University of Haifa                                                    *
 * Reference:                                                                 *
 * S.Gueron and V.Krasnov, "Fast Prime Field Elliptic Curve Cryptography with *
 *                          256 Bit Primes"                                   *
 *                                                                            *
 ******************************************************************************/

 
#include <stdint.h>
#include <string.h>
#include <malloc.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include "cryptlib.h"

#include "ec_lcl.h"

/* structure for precomputed multiples of the generator */
typedef struct ec_pre_comp_st {
    const EC_GROUP *group;              /* Parent EC_GROUP object */
    size_t w;                           /* Window size */
    uint64_t (*precomp)[2][256];        /* Constant time access to the X and Y coordinates of the pre-calculated Generator multiplies, in the Montgomery domain */
                                        /* Pre-calculated multiplies are stored in Affine form, with Z coordinate 1, no need to store explicitly */
    int references;
} EC_PRE_COMP;

/* Functions implemented in ec_p256_funcs_mont.s */
/* Modular shift left. Amount must be <=3 : res = a<<<amount mod P */
void p256_lshift_small(uint64_t res[4], uint64_t a[4], int amount);
/* Modular mul by 2: res = 2*a mod P */
void p256_mul_by_2(uint64_t res[4], uint64_t a[4]);
/* Modular mul by 3: res = 3*a mod P */
void p256_mul_by_3(uint64_t res[4], uint64_t a[4]);
/* Modular mul by 4: res = 4*a mod P */
void p256_mul_by_4(uint64_t res[4], uint64_t a[4]);
/* Modular mul by 8: res = 8*a mod P */
void p256_mul_by_8(uint64_t res[4], uint64_t a[4]);
/* Modular add: res = a+b mod P      */
void p256_add(uint64_t res[4], uint64_t a[4], uint64_t b[4]);
/* Modular sub: res = a-b mod P      */
void p256_sub(uint64_t res[4], uint64_t a[4], uint64_t b[4]);
/* Montgomery mul: res = a*b*2^-256 mod P */
void p256_mul_montl(uint64_t res[4], uint64_t a[4], uint64_t b[4]);
void p256_mul_montx(uint64_t res[4], uint64_t a[4], uint64_t b[4]);
/* Montgomery sqr: res = a*a*2^-256 mod P */
void p256_sqr_montl(uint64_t res[4], uint64_t a[4]);
void p256_sqr_montx(uint64_t res[4], uint64_t a[4]);
/* Convert a number from Montgomery domain, by multiplying with 1 */
void p256_mont_back(uint64_t res[4], uint64_t in[4]);
/* Convert a number to Montgomery domain, by multiplying with 2^512 mod P*/
void p256_to_mont(uint64_t res[4], uint64_t in[4]);

/* One converted into the Montgomery domain */
static const uint64_t ONE[4] = {0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe};

static void *ec_pre_comp_dup(void *);
static void ec_pre_comp_free(void *);
static void ec_pre_comp_clear_free(void *);
static EC_PRE_COMP *ec_pre_comp_new(const EC_GROUP *group);

/* Precomputed tables for the default generator */
extern uint64_t precomputed_ec_p256[43][2][256];

/* Point double: r = 2*a */
static void ec_p256_point_double(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, BN_CTX *ctx, void (*p256_mul_mont)(uint64_t*,uint64_t*,uint64_t*), void (*p256_sqr_mont)(uint64_t*,uint64_t*))
{
    uint64_t S[4];
    uint64_t M[4];
    uint64_t Zsqr[4];
    uint64_t tmp0[4];
    
    uint64_t *in_x = a->X.d;
    uint64_t *in_y = a->Y.d;
    uint64_t *in_z = a->Z.d;
    
    uint64_t *res_x = r->X.d;
    uint64_t *res_y = r->Y.d;
    uint64_t *res_z = r->Z.d;
    
    p256_sqr_mont(S, in_y);
    p256_sqr_mont(Zsqr, in_z);
    
    p256_mul_mont(res_z, in_z, in_y);
    p256_mul_by_2(res_z, res_z);
    
    p256_sqr_mont(res_y, S);
    p256_mul_by_8(res_y, res_y);
    p256_mul_mont(S, S, in_x);
    p256_mul_by_4(S, S);
    p256_add(M, in_x, Zsqr);
    p256_sub(Zsqr, in_x, Zsqr);
    p256_mul_mont(M, M, Zsqr);
    p256_mul_by_3(M, M);
    p256_sqr_mont(res_x, M);
    
    p256_mul_by_2(tmp0, S);
    p256_sub(res_x, res_x, tmp0);
    
    p256_sub(S, S, res_x);
    p256_mul_mont(S, S, M);
    p256_sub(res_y, S, res_y);
}

static uint64_t isZero(uint64_t in)
{
    in |= in<<32;
    in |= in<<16;
    in |= in<<8;
    in |= in<<4;
    in |= in<<2;
    in |= in<<1;
    in = ~in;
    in>>=63;
    return in;
}

static uint64_t isEqual(uint64_t a[4], uint64_t b[4])
{
    uint64_t res;
    
    res = a[0] ^ b[0];
    res |= a[1] ^ b[1];
    res |= a[2] ^ b[2];
    res |= a[3] ^ b[3];
    
    return res == 0 ;
}

static void maskMov(uint64_t dst[4], const uint64_t src[4], uint64_t move)
{
    uint64_t mask1 = -move;
    uint64_t mask2 = ~mask1;
    
    dst[0] = (src[0] & mask1) ^  (dst[0] & mask2);
    dst[1] = (src[1] & mask1) ^  (dst[1] & mask2);
    dst[2] = (src[2] & mask1) ^  (dst[2] & mask2);
    dst[3] = (src[3] & mask1) ^  (dst[3] & mask2);
}

/* Point addition: r = a+b */
static void ec_p256_point_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx, void (*p256_mul_mont)(uint64_t*,uint64_t*,uint64_t*), void (*p256_sqr_mont)(uint64_t*,uint64_t*))
{
    uint64_t U2[4], S2[4];
    uint64_t U1[4], S1[4];
    uint64_t Z1sqr[4];
    uint64_t Z2sqr[4];
    uint64_t H[4], R[4];
    uint64_t Hsqr[4];
    uint64_t Rsqr[4];
    uint64_t Hcub[4];
    
    uint64_t res_x[4];
    uint64_t res_y[4];
    uint64_t res_z[4];
    
    uint64_t z1zero, z2zero;
           
    uint64_t *in1_x = a->X.d;
    uint64_t *in1_y = a->Y.d;
    uint64_t *in1_z = a->Z.d;
           
    uint64_t *in2_x = b->X.d;
    uint64_t *in2_y = b->Y.d;
    uint64_t *in2_z = b->Z.d;
    
    z1zero = in1_z[0] | in1_z[1] | in1_z[2] | in1_z[3];
    z2zero = in2_z[0] | in2_z[1] | in2_z[2] | in2_z[3];
    
    z1zero = isZero(z1zero);
    z2zero = isZero(z2zero);
    
    p256_sqr_mont(Z1sqr, in1_z);             // Z1^2
    p256_sqr_mont(Z2sqr, in2_z);             // Z2^2
    
    p256_mul_mont(U1, in1_x, Z2sqr);         // U1 = X1*Z2^2
    p256_mul_mont(U2, in2_x, Z1sqr);         // U2 = X2*Z1^2
    
    p256_mul_mont(S1, Z2sqr, in2_z);         // S1 = Z2^3
    p256_mul_mont(S2, Z1sqr, in1_z);         // S2 = Z1^3
    
    p256_mul_mont(S1, S1, in1_y);            // S1 = Y1*Z2^3
    p256_mul_mont(S2, S2, in2_y);            // S2 = Y2*Z1^3

    /* This should not happen during sign/ecdh, so no constant time violation */
    if(isEqual(U1, U2) && !z1zero && !z2zero)
    {
        if(isEqual(S1, S2))
        {
            ec_p256_point_double(group, r, a, ctx, p256_mul_mont, p256_sqr_mont);
            return;
        }
        else
        {
            r->X.d[0] = ONE[0];
            r->X.d[1] = ONE[1];
            r->X.d[2] = ONE[2];
            r->X.d[3] = ONE[3];
            r->Y.d[0] = ONE[0];
            r->Y.d[1] = ONE[1];
            r->Y.d[2] = ONE[2];
            r->Y.d[3] = ONE[3];
            r->Z.d[3] = r->Z.d[2] = r->Z.d[1] = r->Z.d[0] = 0;
            return;
        }
    }
    
    p256_sub(H, U2, U1);                    // H = U2 - U1
    p256_sub(R, S2, S1);                    // R = S2 - S1
    
    p256_mul_mont(res_z, H, in1_z);         // Z3 = H*Z1*Z2
    p256_mul_mont(res_z, res_z, in2_z);     // Z3 = H*Z1*Z2

    p256_sqr_mont(Rsqr, R);                 // R^2
    p256_sqr_mont(Hsqr, H);                 // H^2
    p256_mul_mont(Hcub, Hsqr, H);           // H^3
    
    p256_mul_mont(U2, U1, Hsqr);            // U1*H^2
    p256_mul_by_2(Hsqr, U2);                // 2*U1*H^2

    p256_sub(res_x, Rsqr, Hcub);
    p256_sub(res_x, res_x, Hsqr); 
    
    p256_sub(res_y, U2, res_x);
    p256_mul_mont(res_y, res_y, R);
    p256_mul_mont(S2, S1, Hcub);
    p256_sub(res_y, res_y, S2);
    
    maskMov(res_x, in2_x, z1zero);
    maskMov(res_y, in2_y, z1zero);
    maskMov(res_z, in2_z, z1zero);
    
    maskMov(res_x, in1_x, z2zero);
    maskMov(res_y, in1_y, z2zero);
    maskMov(res_z, in1_z, z2zero);
    
    r->X.d[0] = res_x[0];
    r->X.d[1] = res_x[1];
    r->X.d[2] = res_x[2];
    r->X.d[3] = res_x[3];
    
    r->Y.d[0] = res_y[0];
    r->Y.d[1] = res_y[1];
    r->Y.d[2] = res_y[2];
    r->Y.d[3] = res_y[3];
    
    r->Z.d[0] = res_z[0];
    r->Z.d[1] = res_z[1];
    r->Z.d[2] = res_z[2];
    r->Z.d[3] = res_z[3];
}

/* Point addition when b is known to be affine: r = a+b */
static void ec_p256_point_add_affine(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ct, void (*p256_mul_mont)(uint64_t*,uint64_t*,uint64_t*), void (*p256_sqr_mont)(uint64_t*,uint64_t*))
{
    uint64_t U2[4], S2[4];
    uint64_t *U1, *S1;
    uint64_t Z1sqr[4];
    uint64_t H[4], R[4];
    uint64_t Hsqr[4];
    uint64_t Rsqr[4];
    uint64_t Hcub[4];
    
    uint64_t res_x[4];
    uint64_t res_y[4];
    uint64_t res_z[4];
    
    uint64_t z1zero, z2zero;
           
    uint64_t *in1_x = a->X.d;
    uint64_t *in1_y = a->Y.d;
    uint64_t *in1_z = a->Z.d;
           
    uint64_t *in2_x = b->X.d;
    uint64_t *in2_y = b->Y.d;
    
    /* In affine representation we encode infty as (0,0), which is not on the curve, so it is OK */
    z1zero = in1_x[0] | in1_x[1] | in1_x[2] | in1_x[3] | in1_y[0] | in1_y[1] | in1_y[2] | in1_y[3];
    z2zero = in2_x[0] | in2_x[1] | in2_x[2] | in2_x[3] | in2_y[0] | in2_y[1] | in2_y[2] | in2_y[3];
    
    z1zero = isZero(z1zero);
    z2zero = isZero(z2zero);
       
    p256_sqr_mont(Z1sqr, in1_z);                // Z1^2
    
    U1 = in1_x;                                 // U1 = X1*Z2^2
    p256_mul_mont(U2, in2_x, Z1sqr);            // U2 = X2*Z1^2
    
    p256_mul_mont(S2, Z1sqr, in1_z);            // S2 = Z1^3
    
    S1 = in1_y;
    p256_mul_mont(S2, S2, in2_y);               // S2 = Y2*Z1^3
    
    p256_sub(H, U2, U1);                        // H = U2 - U1
    p256_sub(R, S2, S1);                        // R = S2 - S1
    
    p256_mul_mont(res_z, H, in1_z);             // Z3 = H*Z1*Z2
    
    p256_sqr_mont(Rsqr, R);                     // R^2
    p256_sqr_mont(Hsqr, H);                     // H^2
    p256_mul_mont(Hcub, Hsqr, H);               // H^3
    
    p256_mul_mont(U2, U1, Hsqr);                // U1*H^2
    p256_mul_by_2(Hsqr, U2);                    // 2*U1*H^2

    p256_sub(res_x, Rsqr, Hcub);
    p256_sub(res_x, res_x, Hsqr); 
    
    p256_sub(H, U2, res_x);
    p256_mul_mont(H, H, R);
    p256_mul_mont(S2, S1, Hcub);
    p256_sub(res_y, H, S2);
    
    maskMov(res_x, in2_x, z1zero);
    maskMov(res_y, in2_y, z1zero);
    maskMov(res_z, ONE, z1zero);
    
    maskMov(res_x, in1_x, z2zero);
    maskMov(res_y, in1_y, z2zero);
    maskMov(res_z, in1_z, z2zero);
    
    r->X.d[0] = res_x[0];
    r->X.d[1] = res_x[1];
    r->X.d[2] = res_x[2];
    r->X.d[3] = res_x[3];
    
    r->Y.d[0] = res_y[0];
    r->Y.d[1] = res_y[1];
    r->Y.d[2] = res_y[2];
    r->Y.d[3] = res_y[3];
    
    r->Z.d[0] = res_z[0];
    r->Z.d[1] = res_z[1];
    r->Z.d[2] = res_z[2];
    r->Z.d[3] = res_z[3];
}

static void ec_p256_mod_inverse(uint64_t r[4], uint64_t in[4], void (*p256_mul_mont)(uint64_t*,uint64_t*,uint64_t*), void (*p256_sqr_mont)(uint64_t*,uint64_t*))
{
    // The poly is ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff
    // We use FLT and used poly-2 as exponent
    uint64_t p2[4];
    uint64_t p4[4];
    uint64_t p8[4];
    uint64_t p16[4];
    uint64_t p32[4];
    uint64_t res[4];
    int i;
    
    p256_sqr_mont(res, in);
    p256_mul_mont(p2, res, in);          // 3*p
    
    p256_sqr_mont(res, p2);
    p256_sqr_mont(res, res);
    p256_mul_mont(p4, res, p2);          // f*p
    
    p256_sqr_mont(res, p4);
    p256_sqr_mont(res, res);
    p256_sqr_mont(res, res);
    p256_sqr_mont(res, res);
    p256_mul_mont(p8, res, p4);          // ff*p
    
    p256_sqr_mont(res, p8);
    for(i=0; i<7; i++)
    {
        p256_sqr_mont(res, res);
    }
    p256_mul_mont(p16, res, p8);         // ffff*p
    
    p256_sqr_mont(res, p16);
    for(i=0; i<15; i++)
    {
        p256_sqr_mont(res, res);
    }
    p256_mul_mont(p32, res, p16);        // ffffffff*p
    
    p256_sqr_mont(res, p32);
    for(i=0; i<31; i++)
    {
        p256_sqr_mont(res, res);
    }
    p256_mul_mont(res, res, in);
    
    for(i=0; i<32*4; i++)
    {
        p256_sqr_mont(res, res);
    }
    p256_mul_mont(res, res, p32);
    
    for(i=0; i<32; i++)
    {
        p256_sqr_mont(res, res);
    }
    p256_mul_mont(res, res, p32);
    
    for(i=0; i<16; i++)
    {
        p256_sqr_mont(res, res);
    }
    p256_mul_mont(res, res, p16);
    
    for(i=0; i<8; i++)
    {
        p256_sqr_mont(res, res);
    }
    p256_mul_mont(res, res, p8);
    
    for(i=0; i<4; i++)
    {
        p256_sqr_mont(res, res);
    }
    p256_mul_mont(res, res, p4);
    
    for(i=0; i<2; i++)
    {
        p256_sqr_mont(res, res);
    }
    p256_mul_mont(res, res, p2);
    
    for(i=0; i<2; i++)
    {
        p256_sqr_mont(res, res);
    }
    p256_mul_mont(res, res, in);
    
    memcpy(r, res, 32);   
}

static void scatter_w4(void *in_t, void *val, int index)
{
    uint32_t *table = in_t;
    uint32_t *in = val;
    
    int i;
    
    for(i=0; i<8; i++)
    {
        table[index + i*16] = in[i];
    }
}

static void gather_w4(void *val, void *in_t, int index)
{
    uint32_t *table = in_t;
    uint32_t *out = val;
    
    int i;
    
    for(i=0; i<8; i++)
    {
        out[i] = table[index + i*16];
    }
}

void ec_p256_windowed_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM **scalar, const EC_POINT **point, int num, BN_CTX *ctx, void (*p256_mul_mont)(uint64_t*,uint64_t*,uint64_t*), void (*p256_sqr_mont)(uint64_t*,uint64_t*))
{
    int i, j, index;
    EC_POINT *T = NULL, *H = NULL;
    uint8_t (*p_str)[33] = NULL;
    int window_size = 4;
    int mask = (1<<window_size) - 1;
    int wvalue;
    
    BIGNUM **scalars;
        
    uint64_t(*table)[3][16*4] = NULL;
    
    table = memalign(64, num*3*16*4*sizeof(uint64_t));
    p_str = OPENSSL_malloc(num*33*sizeof(uint8_t));    
    scalars = OPENSSL_malloc(num*sizeof(BIGNUM*));
    
    if ((!table) || (!p_str) || (!scalars))
    {
        ECerr(EC_F_P256_MONT_POINTS_MUL_W, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    T = EC_POINT_new(group);
    H = EC_POINT_new(group);

    for(i=0; i<num; i++)
    {
        if((BN_num_bits(scalar[i]) > 256) || (BN_is_negative(scalar[i])))
        {
            if((scalars[i] = BN_CTX_get(ctx)) == NULL)
            {
                goto err;
            }
            if (!BN_nnmod(scalars[i], scalar[i], &group->order, ctx))
            {
                ECerr(EC_F_P256_MONT_POINTS_MUL_W, ERR_R_BN_LIB);
                goto err;
            }
        }
        else
        {
            scalars[i] = scalar[i];
        }
    
        for(j=0; j<((scalars[i]->top)*8); j++) p_str[i][j] =( (uint8_t*)scalars[i]->d)[j];
        for(;j<33; j++) p_str[i][j] = 0;
        
        bn_wexpand(&T->X, 4); T->X.top = 4; memset(T->X.d, 0, 32);
        bn_wexpand(&T->Y, 4); T->Y.top = 4; memset(T->Y.d, 0, 32);
        bn_wexpand(&T->Z, 4); T->Z.top = 4; memset(T->Z.d, 0, 32);

        bn_wexpand(&H->X, 4); H->X.top = 4; memset(H->X.d, 0, 32);
        bn_wexpand(&H->Y, 4); H->Y.top = 4; memset(H->Y.d, 0, 32);
        bn_wexpand(&H->Z, 4); H->Z.top = 4; memset(H->Z.d, 0, 32);

        // Table[0]
        scatter_w4(table[i][0], T->X.d, 0);
        scatter_w4(table[i][1], T->Y.d, 0);
        scatter_w4(table[i][2], T->Z.d, 0);
        // Table[1]
        memcpy(T->X.d, point[i]->X.d, 32);
        memcpy(T->Y.d, point[i]->Y.d, 32);
        memcpy(T->Z.d, point[i]->Z.d, 32);
        
        scatter_w4(table[i][0], T->X.d, 1);
        scatter_w4(table[i][1], T->Y.d, 1);
        scatter_w4(table[i][2], T->Z.d, 1); 
        // Table[2]
        ec_p256_point_double(group, T, T, ctx, p256_mul_mont, p256_sqr_mont);
        
        scatter_w4(table[i][0], T->X.d, 2);
        scatter_w4(table[i][1], T->Y.d, 2);
        scatter_w4(table[i][2], T->Z.d, 2);
        // table[i][3]
        ec_p256_point_add(group, H, T, point[i], ctx, p256_mul_mont, p256_sqr_mont);
        
        scatter_w4(table[i][0], H->X.d, 3);
        scatter_w4(table[i][1], H->Y.d, 3);
        scatter_w4(table[i][2], H->Z.d, 3);
        // table[i][4]
        ec_p256_point_double(group, T, T, ctx, p256_mul_mont, p256_sqr_mont);
        
        scatter_w4(table[i][0], T->X.d, 4);
        scatter_w4(table[i][1], T->Y.d, 4);
        scatter_w4(table[i][2], T->Z.d, 4);
        // table[i][8]
        ec_p256_point_double(group, T, T, ctx, p256_mul_mont, p256_sqr_mont);
        
        scatter_w4(table[i][0], T->X.d, 8);
        scatter_w4(table[i][1], T->Y.d, 8);
        scatter_w4(table[i][2], T->Z.d, 8);
        // table[i][9]
        ec_p256_point_add(group, T, T, point[i], ctx, p256_mul_mont, p256_sqr_mont);
        
        scatter_w4(table[i][0], T->X.d, 9);
        scatter_w4(table[i][1], T->Y.d, 9);
        scatter_w4(table[i][2], T->Z.d, 9);
        // table[i][6]
        ec_p256_point_double(group, H, H, ctx, p256_mul_mont, p256_sqr_mont);
        
        scatter_w4(table[i][0], H->X.d, 6);
        scatter_w4(table[i][1], H->Y.d, 6);
        scatter_w4(table[i][2], H->Z.d, 6);
        // table[i][12]
        ec_p256_point_double(group, H, H, ctx, p256_mul_mont, p256_sqr_mont);
        
        scatter_w4(table[i][0], H->X.d, 12);
        scatter_w4(table[i][1], H->Y.d, 12);
        scatter_w4(table[i][2], H->Z.d, 12);
        // table[i][13]
        ec_p256_point_add(group, H, H, point[i], ctx, p256_mul_mont, p256_sqr_mont);
        
        scatter_w4(table[i][0], H->X.d, 13);
        scatter_w4(table[i][1], H->Y.d, 13);
        scatter_w4(table[i][2], H->Z.d, 13);
        // table[i][5]
        gather_w4(H->X.d, table[i][0], 4);
        gather_w4(H->Y.d, table[i][1], 4);
        gather_w4(H->Z.d, table[i][2], 4);
        
        ec_p256_point_add(group, H, H, point[i], ctx, p256_mul_mont, p256_sqr_mont);
        
        scatter_w4(table[i][0], H->X.d, 5);
        scatter_w4(table[i][1], H->Y.d, 5);
        scatter_w4(table[i][2], H->Z.d, 5);
        // table[i][10]
        ec_p256_point_double(group, H, H, ctx, p256_mul_mont, p256_sqr_mont);
        
        scatter_w4(table[i][0], H->X.d, 10);
        scatter_w4(table[i][1], H->Y.d, 10);
        scatter_w4(table[i][2], H->Z.d, 10);
        // table[i][11]
        ec_p256_point_add(group, H, H, point[i], ctx, p256_mul_mont, p256_sqr_mont);
        
        scatter_w4(table[i][0], H->X.d, 11);
        scatter_w4(table[i][1], H->Y.d, 11);
        scatter_w4(table[i][2], H->Z.d, 11);
        // table[i][7]
        gather_w4(H->X.d, table[i][0], 6);
        gather_w4(H->Y.d, table[i][1], 6);
        gather_w4(H->Z.d, table[i][2], 6);
        
        ec_p256_point_add(group, H, H, point[i], ctx, p256_mul_mont, p256_sqr_mont);
        
        scatter_w4(table[i][0], H->X.d, 7);
        scatter_w4(table[i][1], H->Y.d, 7);
        scatter_w4(table[i][2], H->Z.d, 7);
        // table[i][14]
        ec_p256_point_double(group, H, H, ctx, p256_mul_mont, p256_sqr_mont);
        
        scatter_w4(table[i][0], H->X.d, 14);
        scatter_w4(table[i][1], H->Y.d, 14);
        scatter_w4(table[i][2], H->Z.d, 14);
        // table[i][15]
        ec_p256_point_add(group, H, H, point[i], ctx, p256_mul_mont, p256_sqr_mont);
        
        scatter_w4(table[i][0], H->X.d, 15);
        scatter_w4(table[i][1], H->Y.d, 15);
        scatter_w4(table[i][2], H->Z.d, 15);
    }
    
    index = 252;
        
    wvalue = *((uint8_t*)&p_str[0][index/8]);
    wvalue = (wvalue>> (index%8)) & mask;

    gather_w4(T->X.d, table[0][0], wvalue);
    gather_w4(T->Y.d, table[0][1], wvalue);
    gather_w4(T->Z.d, table[0][2], wvalue);
    
    for(i=1; i<num; i++)
    {
        wvalue = *((uint8_t*)&p_str[i][index/8]);
        wvalue = (wvalue>> (index%8)) & mask;

        gather_w4(H->X.d, table[i][0], wvalue);
        gather_w4(H->Y.d, table[i][1], wvalue);
        gather_w4(H->Z.d, table[i][2], wvalue);
        
        ec_p256_point_add(group, T, T, H, ctx, p256_mul_mont, p256_sqr_mont);
    }
    index-=window_size;
        
    while(index >= 0)   // loop for the remaining windows
    {
        ec_p256_point_double(group, T, T, ctx, p256_mul_mont, p256_sqr_mont);
        ec_p256_point_double(group, T, T, ctx, p256_mul_mont, p256_sqr_mont);
        ec_p256_point_double(group, T, T, ctx, p256_mul_mont, p256_sqr_mont);
        ec_p256_point_double(group, T, T, ctx, p256_mul_mont, p256_sqr_mont);

    
        for(i=0; i<num; i++)
        {
            wvalue = *((unsigned short*)&p_str[i][index/8]);
            wvalue = (wvalue>> (index%8)) & mask;
            gather_w4(H->X.d, table[i][0], wvalue);
            gather_w4(H->Y.d, table[i][1], wvalue);
            gather_w4(H->Z.d, table[i][2], wvalue);
            ec_p256_point_add(group, T, T, H, ctx, p256_mul_mont, p256_sqr_mont);
        }
        
        index-=window_size;
    }
        
    EC_POINT_copy(r, T);
    bn_correct_top(&r->X);
    bn_correct_top(&r->Y);
    bn_correct_top(&r->Z);
    err:
    if(T)
    {
        EC_POINT_free(T);
    }
    if(H)
    {
        EC_POINT_free(H);
    }
    if(table)
    {
        OPENSSL_free(table);
    }
    if(p_str)
    {
        OPENSSL_free(p_str);
    }
    if(scalars)
    {
        OPENSSL_free(scalars);
    }
    
}

static void scatter(void *in_t, void *val, int index)
{
    uint8_t *table = in_t;
    uint8_t *in = val;
    
    int i;
    
    for(i=0; i<32; i++)
    {
        table[index + i*64] = in[i];
    }
}

static void gather(void *val, void *in_t, int index)
{
    uint8_t *table = in_t;
    uint8_t *out = val;
    
    int i;
    
    for(i=0; i<32; i++)
    {
        out[i] = table[index + i*64];
    }
}

int ec_p256_mult_precompute(EC_GROUP *group, BN_CTX *ctx)
{
    // We precompute a table for an "exponent splitting" based computation
    // Each table can hold at most 64 values for safe access.
    // We use the maximal split value of 256/(log2(64)) = 43
	BIGNUM *order;
    EC_POINT *P = NULL, *T = NULL;
    const EC_POINT *generator;
	EC_PRE_COMP *pre_comp;
    int i, j, k, ret = 0;
    size_t w;
    uint64_t buf[4] = {0};
    
    uint64_t(*preComputedTable)[2][256] = NULL;
    
    /* if there is an old EC_PRE_COMP object, throw it away */
    EC_EX_DATA_free_data(&group->extra_data, ec_pre_comp_dup, ec_pre_comp_free, ec_pre_comp_clear_free);

    if ((pre_comp = ec_pre_comp_new(group)) == NULL)
    {
        return 0;
    }
    
    generator = EC_GROUP_get0_generator(group);
    if (generator == NULL)
    {
        ECerr(EC_F_P256_MONT_PRECOMPUTE_MULT, EC_R_UNDEFINED_GENERATOR);
        goto err;
    }

    if (ctx == NULL)
    {
        ctx = BN_CTX_new();
        if (ctx == NULL)
        {
            goto err;
        }
    }
	
    BN_CTX_start(ctx);
    order = BN_CTX_get(ctx);
    
    if (order == NULL)
    {
        goto err;
    }
	
    if (!EC_GROUP_get_order(group, order, ctx)) 
    {
        goto err;
    }
    
    if (BN_is_zero(order))
    {
        ECerr(EC_F_P256_MONT_PRECOMPUTE_MULT, EC_R_UNKNOWN_ORDER);
        goto err;
    }
    
    w = 6;      // We use the maximal window size for which we can store a safe table
    
    preComputedTable = memalign(4096, 43*2*32*(1<<w)*sizeof(uint8_t));
    
    if ((!preComputedTable))
    {
        ECerr(EC_F_P256_MONT_PRECOMPUTE_MULT, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    
    P = EC_POINT_new(group);
    T = EC_POINT_new(group);
        
    for(j=0; j<43; j++)
    {
        scatter(preComputedTable[j][0], buf, 0);
        scatter(preComputedTable[j][1], buf, 0);
    }
    
    EC_POINT_copy(T, generator);
    
    for(k=1; k<64; k++)
    {
        EC_POINT_copy(P, T);
        for(j=0; j<43; j++)
        {
            ec_GFp_simple_make_affine(group, P, ctx);
            scatter(preComputedTable[j][0], P->X.d, k);
            scatter(preComputedTable[j][1], P->Y.d, k);
            for(i=0; i<6; i++)
            {
                ec_GFp_simple_dbl(group, P, P, ctx);
            }
        }
        ec_GFp_simple_add(group, T, T, generator, ctx);
    }
        
    pre_comp->group = group;
    pre_comp->w = w;
    pre_comp->precomp = preComputedTable;
    preComputedTable = NULL;

    if (!EC_EX_DATA_set_data(&group->extra_data, pre_comp,
        ec_pre_comp_dup, ec_pre_comp_free, ec_pre_comp_clear_free))
    {
        goto err;
    }
    
    pre_comp = NULL;

    ret = 1;
    
err:
    if (ctx != NULL)
    {
        BN_CTX_end(ctx);
    }
    if (pre_comp)
    {
        ec_pre_comp_free(pre_comp);
    }
    if (preComputedTable)
    {
        OPENSSL_free(preComputedTable);
    }
    if (P)
    {
        EC_POINT_free(P);
    }
    if (T)
    {
        EC_POINT_free(T);
    }
    return ret;
}

const static uint64_t def_xG[4] = {0x79e730d418a9143c, 0x75ba95fc5fedb601, 0x79fb732b77622510, 0x18905f76a53755c6};
const static uint64_t def_yG[4] = {0xddf25357ce95560a, 0x8b4ab8e4ba19e45c, 0xd2e88688dd21f325, 0x8571ff1825885d85};

#define W_SIZE (6)

int ec_p256_points_mul(
    const EC_GROUP *group, 
    EC_POINT *r, 
    const BIGNUM *scalar,
    size_t num, 
    const EC_POINT *points[], 
    const BIGNUM *scalars[], 
    BN_CTX *ctx)
{    
    int i=0, ret=0;
    uint8_t p_str[33] = {0};
    uint64_t (*preComputedTable)[2][256] = NULL;
	const EC_PRE_COMP *pre_comp = NULL;
	const EC_POINT *generator = NULL;
    int index = 0;
    int mask = (1<<W_SIZE) - 1;
    int wvalue;
    EC_POINT *T;
    BIGNUM *tmp_scalar;
    
    void (*p256_mul_mont)(uint64_t*,uint64_t*,uint64_t*) = NULL;
    void (*p256_sqr_mont)(uint64_t*,uint64_t*) = NULL;
    

    if((OPENSSL_ia32cap_P[2]&0x80100) == 0x80100)
    {
        p256_mul_mont = p256_mul_montx;
        p256_sqr_mont = p256_sqr_montx;
    }
    else
    {
        p256_mul_mont = p256_mul_montl;
        p256_sqr_mont = p256_sqr_montl;
    }
    
    
    if (group->meth != r->meth)
    {
        ECerr(EC_F_P256_MONT_POINTS_MUL, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }

    if ((scalar == NULL) && (num == 0))
    {
        return EC_POINT_set_to_infinity(group, r);
    }

    for (i = 0; i < num; i++)
    {
        if (group->meth != points[i]->meth)
        {
            ECerr(EC_F_P256_MONT_POINTS_MUL, EC_R_INCOMPATIBLE_OBJECTS);
            return 0;
        }
    }
    
    T = EC_POINT_new(group);
    
    bn_wexpand(&r->X, 4);
    bn_wexpand(&r->Y, 4);
    bn_wexpand(&r->Z, 4);
    bn_wexpand(&T->X, 4);
    bn_wexpand(&T->Y, 4);
    bn_wexpand(&T->Z, 4);
    
    r->X.top = 4;
    r->Y.top = 4;
    r->Z.top = 4;
    
    T->X.top = 4;
    T->Y.top = 4;
    T->Z.top = 4;
    
    if(scalar)
    {
        generator = EC_GROUP_get0_generator(group);
        if (generator == NULL)
        {
            ECerr(EC_F_P256_MONT_POINTS_MUL, EC_R_UNDEFINED_GENERATOR);
            goto err;
        }
        
		/* look if we can use precomputed multiples of generator */
        pre_comp = EC_EX_DATA_get_data(group->extra_data, ec_pre_comp_dup, ec_pre_comp_free, ec_pre_comp_clear_free);
        
        if(pre_comp)
        {            
            preComputedTable = pre_comp->precomp;
        }
        /* If no precompute but using the default generator */
        /* Why use hardcoded precomputed tables? Because some applications such
           as Apache, do not use EC_KEY_precompute_mult */
        else if(
            (generator->X.d[0] == def_xG[0]) &&
            (generator->X.d[1] == def_xG[1]) &&
            (generator->X.d[2] == def_xG[2]) &&
            (generator->X.d[3] == def_xG[3]) &&
            (generator->Y.d[0] == def_yG[0]) &&
            (generator->Y.d[1] == def_yG[1]) &&
            (generator->Y.d[2] == def_yG[2]) &&
            (generator->Y.d[3] == def_yG[3]) &&
            (generator->Z.d[0] == ONE[0]) &&
            (generator->Z.d[1] == ONE[1]) &&
            (generator->Z.d[2] == ONE[2]) &&
            (generator->Z.d[3] == ONE[3]))
        {
            preComputedTable = precomputed_ec_p256;
        }
        
        if(preComputedTable)
        {
            if((BN_num_bits(scalar) > 256) || (BN_is_negative(scalar)))
            {
                if((tmp_scalar = BN_CTX_get(ctx)) == NULL)
                {
                    goto err;
                }
                if (!BN_nnmod(tmp_scalar, scalar, &group->order, ctx))
                {
                    ECerr(EC_F_P256_MONT_POINTS_MUL, ERR_R_BN_LIB);
                    goto err;
                }
                scalar = tmp_scalar;
            }
            for(i=0; i<((scalar->top)*8); i++)
            {
                p_str[i] =( (uint8_t*)scalar->d)[i];
            }
            for(;i<33; i++)
            {
                p_str[i] = 0;
            }
        
            // First window
            wvalue = *((uint16_t*)&p_str[index/8]);
            wvalue = (wvalue>> (index%8)) & mask;
            index += W_SIZE;
            
            gather(r->X.d, preComputedTable[0][0], wvalue);
            gather(r->Y.d, preComputedTable[0][1], wvalue);
            
            memcpy(r->Z.d, ONE, 32);
            memcpy(T->Z.d, ONE, 32);
                    
            for(i=1; i<43; i++)
            {        
                wvalue = *((uint16_t*)&p_str[index/8]);
                wvalue = (wvalue>> (index%8)) & mask;
                index+=W_SIZE;
            
                gather(T->X.d, preComputedTable[i][0], wvalue);
                gather(T->Y.d, preComputedTable[i][1], wvalue);
                
                ec_p256_point_add_affine(group, r, r, T, ctx, p256_mul_mont, p256_sqr_mont);
            }
        }
        else
        {
            ec_p256_windowed_mul(group, r, &scalar, &generator, 1, ctx, p256_mul_mont, p256_sqr_mont);
        }
    }
    else
    {
        memset(r->X.d, 0, 32);
        memset(r->Y.d, 0, 32);
        memset(r->Z.d, 0, 32);
    }

    if(num)
    {
        ec_p256_windowed_mul(group, T, scalars, points, num, ctx, p256_mul_mont, p256_sqr_mont);
        ec_p256_point_add(group, r, r, T, ctx, p256_mul_mont, p256_sqr_mont);
    }    
    
    bn_correct_top(&r->X);
    bn_correct_top(&r->Y);
    bn_correct_top(&r->Z);
    
    ret = 1;
    err:
    if(T)
    {
        EC_POINT_free(T);
    }
    return ret;
}

int ec_p256_get_affine(const EC_GROUP *group,
    const EC_POINT *point, BIGNUM *x, BIGNUM *y, BN_CTX *ctx)
{
    
    uint64_t z_inv2[4];
    uint64_t z_inv3[4];
    uint64_t x_aff[4];
    uint64_t y_aff[4];    

    void (*p256_mul_mont)(uint64_t*,uint64_t*,uint64_t*) = NULL;
    void (*p256_sqr_mont)(uint64_t*,uint64_t*) = NULL;
    

    if((OPENSSL_ia32cap_P[2]&0x80100) == 0x80100)
    {
        p256_mul_mont = p256_mul_montx;
        p256_sqr_mont = p256_sqr_montx;
    }
    else
    {
        p256_mul_mont = p256_mul_montl;
        p256_sqr_mont = p256_sqr_montl;
    }
    
    if (EC_POINT_is_at_infinity(group, point))
    {
        ECerr(EC_F_P256_MONT_GET_AFFINE_COORDINATES,
                EC_R_POINT_AT_INFINITY);
        return 0;
    }
    
    ec_p256_mod_inverse(z_inv3, point->Z.d, p256_mul_mont, p256_sqr_mont);
    p256_sqr_mont(z_inv2, z_inv3);
    p256_mul_mont(x_aff, z_inv2, point->X.d);
    
    if(x != NULL)
    {   
        bn_wexpand(x, 4);    
        x->top = 4;
        p256_mont_back(x->d, x_aff);
        bn_correct_top(x);
    }
    
    if(y != NULL)
    {
        p256_mul_mont(z_inv3, z_inv3, z_inv2);
        p256_mul_mont(y_aff, z_inv3, point->Y.d);
        bn_wexpand(y, 4);
        y->top = 4;        
        p256_mont_back(y->d, y_aff);        
        bn_correct_top(y);  
    }    
    
	return 1;
}

static EC_PRE_COMP *ec_pre_comp_new(const EC_GROUP *group)
{
    EC_PRE_COMP *ret = NULL;

    if (!group)
    {
        return NULL;
    }

    ret = (EC_PRE_COMP *)OPENSSL_malloc(sizeof(EC_PRE_COMP));
    
    if (!ret)
    {
        ECerr(EC_F_P256_MONT_PRE_COMP_NEW, ERR_R_MALLOC_FAILURE);
        return ret;
    }
    
    ret->group = group;
    ret->w = 6; /* default */
    ret->precomp = NULL;
    ret->references = 1;
    return ret;
}

static void *ec_pre_comp_dup(void *src_)
{
	EC_PRE_COMP *src = src_;

	/* no need to actually copy, these objects never change! */

	CRYPTO_add(&src->references, 1, CRYPTO_LOCK_EC_PRE_COMP);

	return src_;
}

static void ec_pre_comp_free(void *pre_)
{
    int i;
    EC_PRE_COMP *pre = pre_;

    if (!pre)
    {
        return;
    }

    i = CRYPTO_add(&pre->references, -1, CRYPTO_LOCK_EC_PRE_COMP);
    if (i > 0)
    {
        return;
    }
    if (pre->precomp)
    {
        OPENSSL_free(pre->precomp);
    }
    OPENSSL_free(pre);
}

static void ec_pre_comp_clear_free(void *pre_)
{
    int i;
    EC_PRE_COMP *pre = pre_;

    if (!pre)
    {
        return;
    }

    i = CRYPTO_add(&pre->references, -1, CRYPTO_LOCK_EC_PRE_COMP);
    if (i > 0)
    {
        return;
    }
    if (pre->precomp)
    {
        OPENSSL_cleanse(pre->precomp, 32*sizeof(uint8_t)*(1<<pre->w)*2*43);
        OPENSSL_free(pre->precomp);
    }
    OPENSSL_cleanse(pre, sizeof *pre);
    OPENSSL_free(pre);
}

int ec_p256_window_have_precompute_mult(const EC_GROUP *group)
{
    if (EC_EX_DATA_get_data(group->extra_data, ec_pre_comp_dup, ec_pre_comp_free, ec_pre_comp_clear_free) != NULL)
        return 1;
    else
        return 0;
}

const EC_METHOD *EC_GFp_mont_p256_method(void)
	{
	static const EC_METHOD ret = {
		EC_FLAGS_DEFAULT_OCT,
		NID_X9_62_prime_field,
		ec_GFp_mont_group_init,
		ec_GFp_mont_group_finish,
		ec_GFp_mont_group_clear_finish,
		ec_GFp_mont_group_copy,
		ec_GFp_mont_group_set_curve,
		ec_GFp_simple_group_get_curve,
		ec_GFp_simple_group_get_degree,
		ec_GFp_simple_group_check_discriminant,
		ec_GFp_simple_point_init,
		ec_GFp_simple_point_finish,
		ec_GFp_simple_point_clear_finish,
		ec_GFp_simple_point_copy,
		ec_GFp_simple_point_set_to_infinity,
		ec_GFp_simple_set_Jprojective_coordinates_GFp,
		ec_GFp_simple_get_Jprojective_coordinates_GFp,
		ec_GFp_simple_point_set_affine_coordinates,
		ec_p256_get_affine,
		0,0,0,
		ec_GFp_simple_add,
		ec_GFp_simple_dbl,
		ec_GFp_simple_invert,
		ec_GFp_simple_is_at_infinity,
		ec_GFp_simple_is_on_curve,
		ec_GFp_simple_cmp,
		ec_GFp_simple_make_affine,
		ec_GFp_simple_points_make_affine,
		ec_p256_points_mul                  /* mul */,
		ec_p256_mult_precompute             /* precompute_mult */,
		ec_p256_window_have_precompute_mult /* have_precompute_mult */,	
		ec_GFp_mont_field_mul,
		ec_GFp_mont_field_sqr,
		0 /* field_div */,
		ec_GFp_mont_field_encode,
		ec_GFp_mont_field_decode,
		ec_GFp_mont_field_set_to_one };

	return &ret;
	}
