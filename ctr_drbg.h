#ifndef __PLUS__
#define __PLUS__
/*
    암호최적화 연구실
    20175204 김영범
    2020년 05월 13일
*/

//! header file
#include <stdio.h>
#include <time.h>
#include <memory.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


typedef unsigned char u8;
#define KEY_BIT 128
#define BLOCK_BIT 128
#define LEN_SEED (KEY_BIT + BLOCK_BIT)/BLOCK_BIT
#define BLOCK_SIZE 16
#define N_DF (KEY_BIT + BLOCK_BIT)/8
#define TRUE  1
#define FALSE  0


typedef struct _IN_state {   
    unsigned char key[16];   
    unsigned char V[16];     
    unsigned char Reseed_counter;
    unsigned char prediction_flag;
} in_state;

typedef struct LEN {   
    unsigned char add_data;   
    unsigned char re_adddata;     
    unsigned char re_Entrophy;
    unsigned char seed; 
    unsigned char general_len;
} st_len;

void XoR(unsigned char* drc, unsigned char* src, int len);
void set_state(unsigned char* drc, unsigned char* src , int start);
void copy_state(unsigned char drc[LEN_SEED][BLOCK_SIZE], unsigned char * src, int len);
void copy(unsigned char *drc, unsigned char * src);
void clear(unsigned char *src, int len);

void df(unsigned char *input_data,unsigned char* seed, unsigned char *input_len);
void update(in_state* state,unsigned char* seed);
void gf(in_state *state, unsigned char *random, unsigned char *add_data, unsigned char *re_Entrophy, unsigned char *re_add_data,st_len* LEN);
void Reseed_Function(in_state* state,unsigned char *re_Entrophy,unsigned char *re_add_data,st_len* LEN);


//! ARIA
void DL(const u8 *i, u8 *o);
void RotXOR(const u8 *s, int n, u8 *t);
int EncKeySetup(const u8 *w0, u8 *e, int keyBits);
void Crypt(const u8 *p, int R, const u8 *e, u8 *c);



#endif