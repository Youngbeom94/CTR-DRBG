#include "header.h"

void derived_function_Optimize(u8 *input_data, u8 *seed, u8* LUK_Table)
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




void Optimize_CTR_DRBG(st_state *in_state, u8 *in, u8 *seed, u8 *random, u8 *re_add_data, u8* LUK_Table)
{
    derived_function_Optimize(in, seed,LUK_Table);
    generate_Random(in_state, random,re_add_data);
}
