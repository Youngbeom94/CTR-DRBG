#include "header.h"

void derived_function(u8 *input_data, u8 *seed)
{
    volatile int cnt_i = 0, cnt_j = 0, cnt_k = 0;
    u8 CBC_KEY[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    u8 chain_value[BLOCK_SIZE] = {0x00};
    u8 KEYandV[LEN_SEED * BLOCK_SIZE] = {0x00};
    u8 in[DF_INPUT_LEN] = {0x00};

    for (cnt_i = 0; cnt_i < INSTANCE_INPUT; cnt_i++)
    {
        in[cnt_i + 24] = input_data[cnt_i];
    }
    in[cnt_i] = N_CONSTANT;
    in[19] = INSTANCE_INPUT;
    in[23] = N_DF;
    in[24 + INSTANCE_INPUT] = 0x80;

    u8 state[BLOCK_SIZE] = {0x00};
    /*
* AVR function Setting
*/
    u8 round_key[16 * 17] = {0x00};

    //! step1
    for (cnt_j = 0; cnt_j < LEN_SEED; cnt_j++)
    {
        for (cnt_i = 0; cnt_i < DF_INPUT_LEN / 16; cnt_i++)
        {
            set_state(state, in, 16 * cnt_i);
            XoR(state, chain_value, BLOCK_SIZE);
            //!Function
            Crypt(state, EncKeySetup(CBC_KEY, round_key, 128), round_key, chain_value);
        }
        copy_state(KEYandV, chain_value, cnt_j);
        clear(chain_value, BLOCK_SIZE);
        in[3]++;
    }

    //! step2
    u8 key[16] = {0x00};
    for (cnt_i = 0; cnt_i < KEY_SIZE; cnt_i++)
    {
        key[cnt_i] = KEYandV[cnt_i];
    }
    for (cnt_i = KEY_SIZE; cnt_i < SEED_LEN; cnt_i++)
    {
        state[cnt_i] = KEYandV[cnt_i];
    }

    for (cnt_i = 0; cnt_i < LEN_SEED; cnt_i++)
    {
        //!Function
        Crypt(state, EncKeySetup(key, round_key, 128), round_key, chain_value);
        for (cnt_j = 0; cnt_j < BLOCK_SIZE; cnt_j++)
        {
            seed[cnt_i * BLOCK_SIZE + cnt_j] = chain_value[cnt_j];
            state[cnt_j] = chain_value[cnt_j];
        }
    }
   
}

void update(st_state *state, u8 *seed)
{
    volatile int cnt_i = 0, cnt_j = 0, cnt_k = 0;
    u8 result[BLOCK_SIZE] = {0x00};
    u8 temp[32] = {0x00};

    /*
    * AVR function Setting
    */
    u8 round_key[(KEY_BIT/8)* 17] = {0x00};

    for (cnt_i = 0; cnt_i < LEN_SEED; cnt_i++)
    {
        state->V[BLOCK_SIZE - 1]++;
        //! Function
        Crypt(state->V, EncKeySetup(state->key, round_key, KEY_BIT), round_key, result);
        for (cnt_j = 0; cnt_j < BLOCK_SIZE; cnt_j++)
        {
            temp[cnt_i * BLOCK_SIZE + cnt_j] = result[cnt_j];
        }
    }
    for (cnt_i = 0; cnt_i < KEY_SIZE; cnt_i++)
    {
        state->key[cnt_i] = temp[cnt_i] ^ seed[cnt_i];
    }
    for (cnt_i = 0 ; cnt_i < BLOCK_SIZE; cnt_i++)
    {
        state->V[cnt_i] = temp[KEY_SIZE + cnt_i] ^ seed[KEY_SIZE + cnt_i];
    }


    //  for (cnt_k = 0; cnt_k < KEY_SIZE; cnt_k++)
    // {
    //     printf("%02x ", state->key[cnt_k]);
    // }
    // printf("\n");
    //  for (cnt_k = 0; cnt_k < BLOCK_SIZE; cnt_k++)
    // {
    //     printf("%02x ", state->V[cnt_k]);
    // }
}

// void generate_Random(st_state *state, u8 *random, u8 *add_data, u8 *re_Entrophy, u8 *re_add_data, st_len *LEN)
// {

//     int cnt_i, cnt_j, cnt_k = 0;
//     u8 round_key[16 * 17] = {0x00};
//     u8 result[16] = {0x00};
//     u8 a_data[16] = {0x00};
//     u8 seed[32] = {0x00};
//     u8 temp[32] = {0x00};

//     if (state->prediction_flag == TRUE)
//     {
//         Reseed_Function(state, re_Entrophy, re_add_data, LEN);
//         add_data = NULL;
//         derived_function(a_data, seed, &(LEN->general_len));
//         for (cnt_i = 0; cnt_i < LEN_SEED; cnt_i++)
//         {
//             state->V[15]++;
//             Crypt(state->V, EncKeySetup(state->key, round_key, 128), round_key, result);
//             for (cnt_j = 0; cnt_j < BLOCK_SIZE; cnt_j++)
//             {
//                 random[cnt_i * 16 + cnt_j] = result[cnt_j];
//             }
//         }
//         for (cnt_i = 0; cnt_i < LEN_SEED; cnt_i++)
//         {
//             state->V[15]++;
//             Crypt(state->V, EncKeySetup(state->key, round_key, 128), round_key, result);
//             for (cnt_j = 0; cnt_j < BLOCK_SIZE; cnt_j++)
//             {
//                 temp[cnt_i * 16 + cnt_j] = result[cnt_j];
//             }
//         }
//         for (cnt_i = 0; cnt_i < 32; cnt_i++)
//         {
//             temp[cnt_i] ^= seed[cnt_i];
//         }
//         for (cnt_i = 0; cnt_i < 16; cnt_i++)
//         {
//             state->key[cnt_i] = temp[cnt_i] ^ seed[cnt_i];
//             state->V[cnt_i] = temp[16 + cnt_i] ^ seed[16 + cnt_i];
//         }
//     }

//     else if (add_data != NULL)
//     {
//         derived_function(add_data, seed, &(LEN->general_len));
//         update(state, seed);
//         for (cnt_i = 0; cnt_i < LEN_SEED; cnt_i++)
//         {
//             state->V[15]++;
//             Crypt(state->V, EncKeySetup(state->key, round_key, 128), round_key, result);
//             for (cnt_j = 0; cnt_j < BLOCK_SIZE; cnt_j++)
//             {
//                 random[cnt_i * 16 + cnt_j] = result[cnt_j];
//             }
//         }
//         for (cnt_i = 0; cnt_i < LEN_SEED; cnt_i++)
//         {
//             state->V[15]++;
//             Crypt(state->V, EncKeySetup(state->key, round_key, 128), round_key, result);
//             for (cnt_j = 0; cnt_j < BLOCK_SIZE; cnt_j++)
//             {
//                 temp[cnt_i * 16 + cnt_j] = result[cnt_j];
//             }
//         }
//         for (cnt_i = 0; cnt_i < 32; cnt_i++)
//         {
//             temp[cnt_i] ^= seed[cnt_i];
//         }
//         for (cnt_i = 0; cnt_i < 16; cnt_i++)
//         {
//             state->key[cnt_i] = temp[cnt_i] ^ seed[cnt_i];
//             state->V[cnt_i] = temp[16 + cnt_i] ^ seed[16 + cnt_i];
//         }
//     }

//     else
//     {
//         derived_function(a_data, seed, &(LEN->general_len));
//         for (cnt_i = 0; cnt_i < LEN_SEED; cnt_i++)
//         {
//             state->V[15]++;
//             Crypt(state->V, EncKeySetup(state->key, round_key, 128), round_key, result);
//             for (cnt_j = 0; cnt_j < BLOCK_SIZE; cnt_j++)
//             {
//                 random[cnt_i * 16 + cnt_j] = result[cnt_j];
//             }
//         }

//         for (cnt_i = 0; cnt_i < LEN_SEED; cnt_i++)
//         {
//             state->V[15]++;
//             Crypt(state->V, EncKeySetup(state->key, round_key, 128), round_key, result);
//             for (cnt_j = 0; cnt_j < BLOCK_SIZE; cnt_j++)
//             {
//                 temp[cnt_i * 16 + cnt_j] = result[cnt_j];
//             }
//         }
//         for (cnt_i = 0; cnt_i < 32; cnt_i++)
//         {
//             temp[cnt_i] ^= seed[cnt_i];
//         }
//         for (cnt_i = 0; cnt_i < 16; cnt_i++)
//         {
//             state->key[cnt_i] = temp[cnt_i] ^ seed[cnt_i];
//             state->V[cnt_i] = temp[16 + cnt_i] ^ seed[16 + cnt_i];
//         }
//     }
//     state->Reseed_counter++;
// }

// void Reseed_Function(st_state *state, u8 *re_Entrophy, u8 *re_add_data, st_len *len)
// {
//     int cnt_i = 0;
//     u8 len2 = len->re_adddata + len->re_Entrophy;
//     u8 *input_data = (u8 *)calloc(len2, sizeof(u8));
//     u8 seed[32] = {0x00};
//     for (cnt_i = 0; cnt_i < len->re_Entrophy; cnt_i++)
//     {
//         input_data[cnt_i] = re_Entrophy[cnt_i];
//     }
//     for (cnt_i = len->re_Entrophy; cnt_i < len2; cnt_i++)
//     {
//         input_data[cnt_i] = re_Entrophy[cnt_i - len->re_Entrophy];
//     }
//     derived_function(input_data, seed, &len2);
//     update(state, seed);
//     free(input_data);
// }

void CTR_DRBG(st_state *in_state, st_len *len, u8 *in, u8 *seed, u8 *random, u8 *re_add_data, u8 *re_Entrophy, u8 *add_data)
{
    derived_function(in, seed);
    update(in_state, seed);
    // generate_Random(in_state, random,add_data,re_Entrophy,re_add_data,len);
}

void XoR(u8 *drc, u8 *src, int len)
{
    for (volatile int cnt_i = 0; cnt_i < len; cnt_i++)
    {
        drc[cnt_i] ^= src[cnt_i];
    }
}
void set_state(u8 *drc, u8 *src, int start)
{
    for (volatile int cnt_i = 0; cnt_i < BLOCK_SIZE; cnt_i++)
    {
        drc[cnt_i] = src[start + cnt_i];
    }
}
void copy_state(u8 *drc, u8 *src, int len)
{
    for (volatile int cnt_i = 0; cnt_i < BLOCK_SIZE; cnt_i++)
    {
        drc[16 * len + cnt_i] = src[cnt_i];
    }
}
void copy(u8 *drc, u8 *src)
{
    for (volatile int cnt_i = 0; cnt_i < BLOCK_SIZE; cnt_i++)
    {
        drc[cnt_i] = src[cnt_i];
    }
}
void clear(u8 *src, int len)
{
    for (volatile int cnt_i = 0; cnt_i < len; cnt_i++)
    {
        src[cnt_i] = 0x00;
    }
}