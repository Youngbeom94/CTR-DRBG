#include "ctr_drbg.h"


int main()
{
    int cnt_i = 0;
    unsigned char in[24] = {0x3D,0xA9,0x3E,0xDD,0x17,0x94,0x4F,0x79,0x1E,0x33,0x99,0x67,0x2C,0xC6,0xEA,0x93,0x8A,0x3F,0xFF,0x14,0x09,0x02,0x3D,0x0C};
    unsigned char seed[32] = {0x00};
    unsigned char len = 24;


    unsigned char input_data[32] = {0x00};
    in_state INSTATE = {0x00,};
    in_state *IN_state = &INSTATE;
    st_len st_LEN = {0x00};
    st_len *LEN = &st_LEN;
    IN_state->prediction_flag = 0;
    LEN->add_data = 16;
    LEN->general_len = 16;
    LEN->re_adddata = 16;
    LEN->re_Entrophy = 16;
    LEN->seed = 32;
    unsigned char random[16] = {0x00};
    unsigned char add_data = NULL;
    unsigned char re_Entrophy[16] = {0x4E,0xE9,0xA2,0xCF,0x6E,0x8B,0xFA,0x48,0xBB,0xBE,0x56,0x99,0xDD,0x5A,0xBA,0x02};
    unsigned char re_add_data[1] = {0x00};

    df(in,seed,&len);
    update(IN_state,seed);
    gf(IN_state, random,add_data,re_Entrophy, re_add_data,LEN);
    printf("\n");
    for(cnt_i = 0 ; cnt_i <16 ; cnt_i ++)
    {
        printf("%02x ",random[cnt_i]);
    }
    // printf("\n");
    // for(cnt_i = 0 ; cnt_i <16 ; cnt_i ++)
    // {
    //     printf("%02x ",IN_state->key[cnt_i]);
    // }
    // printf("\n");
    // for(cnt_i = 0 ; cnt_i <16 ; cnt_i ++)
    // {
    //     printf("%02x ",IN_state->V[cnt_i]);
    // }
    return 0;
}