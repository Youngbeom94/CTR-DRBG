#ifndef __PLUS__
#define __PLUS__
/*
    암호최적화 연구실
    20175204 김영범
    2020년 05월 13일
*/

//! header file
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <stdlib.h>

/*
*   choose your block Cipher, using flag
*
*   HIGHT = 0,
*   LEA_128 = 1,
*   LEA_192 = 2,
*   LEA_256 = 3,
*   CHAM_64_128 = 4,
*   CHAM_128_128 = 5,
*   CHAM_128_256 = 6
*/
#define BLOCK_CIPHER  0


#if BLOCK_CIPHER == 0 //HIGHT
    #define KEY_BIT 128
    #define BLOCK_BIT 128
    #define LEN_SEED (KEY_BIT + BLOCK_BIT)/BLOCK_BIT
    #define BLOCK_SIZE 16
    #define N_DF (KEY_BIT + BLOCK_BIT)>>3

#elif BLOCK_CIPHER == 1 // LEA_128
    #define KEY_BIT 128
    #define BLOCK_BIT 128
    #define LEN_SEED (KEY_BIT + BLOCK_BIT)/BLOCK_BIT
    #define BLOCK_SIZE 16
    #define N_DF (KEY_BIT + BLOCK_BIT)>>3
#elif BLOCK_CIPHER == 2 // LEA_192

    #define BLOCK_BIT 128
    #define LEN_SEED (KEY_BIT + BLOCK_BIT)/BLOCK_BIT
    #define BLOCK_SIZE 16
    #define N_DF (KEY_BIT + BLOCK_BIT)>>3

#elif BLOCK_CIPHER == 3 // LEA_256
   #define BLOCK_BIT 128
    #define LEN_SEED (KEY_BIT + BLOCK_BIT)/BLOCK_BIT
    #define BLOCK_SIZE 16
    #define N_DF (KEY_BIT + BLOCK_BIT)>>3

#elif BLOCK_CIPHER == 4 // CHAM_64_128
   #define BLOCK_BIT 128
    #define LEN_SEED (KEY_BIT + BLOCK_BIT)/BLOCK_BIT
    #define BLOCK_SIZE 16
    #define N_DF (KEY_BIT + BLOCK_BIT)>>3

#elif BLOCK_CIPHER == 5 // CHAM_128_128
   #define BLOCK_BIT 128
    #define LEN_SEED (KEY_BIT + BLOCK_BIT)/BLOCK_BIT
    #define BLOCK_SIZE 16
    #define N_DF (KEY_BIT + BLOCK_BIT)>>3

#else //CHAM_128_256

   #define BLOCK_BIT 128
    #define LEN_SEED (KEY_BIT + BLOCK_BIT)/BLOCK_BIT
    #define BLOCK_SIZE 16
    #define N_DF (KEY_BIT + BLOCK_BIT)>>3
#endif


#define TRUE  1
#define FALSE  0

typedef unsigned char u8;

typedef struct _IN_state {   
    u8 key[16];   
    u8 V[16];     
    u8 Reseed_counter;
    u8 prediction_flag;
} st_state;

typedef struct LEN {   
    u8 add_data;   
    u8 re_adddata;     
    u8 re_Entrophy;
    u8 seed; 
    u8 general_len;
    u8 input_len;
} st_len;

void XoR(u8* drc, u8* src, int len);
void set_state(u8* drc, u8* src , int start);
void copy_state(u8 drc[LEN_SEED][BLOCK_SIZE], u8 * src, int len);
void copy(u8 *drc, u8 * src);
void clear(u8 *src, int len);

void derived_function(u8 *input_data,u8* seed, u8 *input_len);
void update(st_state* state,u8* seed);
void generate_Random(st_state *state, u8 *random, u8 *add_data, u8 *re_Entrophy, u8 *re_add_data,st_len* LEN);
void Reseed_Function(st_state* state,u8 *re_Entrophy,u8 *re_add_data,st_len* LEN);
void CTR_DRBG(st_state* in_state, st_len* len,u8* in, u8* seed,u8* random,u8* re_add_data,u8 *re_Entrophy,u8 *add_data);

//! ARIA
void DL(const u8 *i, u8 *o);
void RotXOR(const u8 *s, int n, u8 *t);
int EncKeySetup(const u8 *w0, u8 *e, int keyBits);
void Crypt(const u8 *p, int R, const u8 *e, u8 *c);



#endif