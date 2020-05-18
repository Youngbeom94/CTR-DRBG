#include "ctr_drbg.h"

void XoR(unsigned char *drc, unsigned char *src, int len)
{
    for (int cnt_i = 0; cnt_i < len; cnt_i++)
    {
        drc[cnt_i] ^= src[cnt_i];
    }
}
void set_state(unsigned char *drc, unsigned char *src, int start)
{
    for (int cnt_i = 0; cnt_i < BLOCK_SIZE; cnt_i++)
    {
        drc[cnt_i] = src[start + cnt_i];
    }
}
void copy_state(unsigned char drc[LEN_SEED][BLOCK_SIZE], unsigned char *src, int len)
{
    for (int cnt_i = 0; cnt_i < BLOCK_SIZE; cnt_i++)
    {
        drc[len][cnt_i] = src[cnt_i];
        // printf("%02x ",drc[len][cnt_i]);
    }
}
void copy(unsigned char *drc, unsigned char *src)
{
    for (int cnt_i = 0; cnt_i < BLOCK_SIZE; cnt_i++)
    {
        drc[cnt_i] = src[cnt_i];
    }
}
void clear(unsigned char *src, int len)
{
    for (int cnt_i = 0; cnt_i < len; cnt_i++)
    {
        src[cnt_i] = 0x00;
    }
}
void df(unsigned char *input_data, unsigned char *seed, unsigned char *input_len)
{
    int cnt_i, cnt_j, cnt_k = 0;
    unsigned int len = 25 + *input_len;
    unsigned char temp = len % BLOCK_SIZE;
    unsigned char CBC_KEY[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char round_key[16 * 17] = {0x00};
    unsigned char chain_value[16] = {0x00};
    unsigned char KEYandV[LEN_SEED][16] = {0x00};
    if (temp != 0)
        len += BLOCK_SIZE - temp;

    unsigned char *in = (unsigned char *)calloc(len, sizeof(unsigned char));
    in[19] = *input_len;
    in[23] = N_DF;
    for (cnt_i = 24; cnt_i < 24 + *input_len; cnt_i++)
        in[cnt_i] = input_data[cnt_i - 24];
    in[cnt_i] = 0x80;

    unsigned char state[16] = {0x00};
    for (cnt_j = 0; cnt_j < 2; cnt_j++)
    {
        for (cnt_i = 0; cnt_i < len / 16; cnt_i++)
        {
            set_state(state, in, 16 * cnt_i);
            XoR(state, chain_value, BLOCK_SIZE);
            Crypt(state, EncKeySetup(CBC_KEY, round_key, 128), round_key, chain_value);
            // printf("\n");
            // for (int cnt_k = 0; cnt_k < 16; cnt_k++)
            // {
            //     printf("%02x ", chain_value[cnt_k]);
            // }
        }
        copy_state(KEYandV, chain_value, cnt_j);
        clear(chain_value, BLOCK_SIZE);
        in[3]++;
    }

    //! step2
    unsigned char key[16] = {0x00};
    for (cnt_i = 0; cnt_i < BLOCK_SIZE; cnt_i++)
    {
        key[cnt_i] = KEYandV[0][cnt_i];
        state[cnt_i] = KEYandV[1][cnt_i];
    }
    // printf("\n");
    // for (int cnt_k = 0; cnt_k < 16; cnt_k++)
    // {
    //     printf("%02x ", key[cnt_k]);
    // }
    // printf("\n");
    // for (int cnt_k = 0; cnt_k < 16; cnt_k++)
    // {
    //     printf("%02x ", state[cnt_k]);
    // }

    for (cnt_i = 0; cnt_i < LEN_SEED; cnt_i++)
    {
        Crypt(state, EncKeySetup(key, round_key, 128), round_key, chain_value);
        for (cnt_j = 0; cnt_j < BLOCK_SIZE; cnt_j++)
        {
            seed[cnt_i * 16 + cnt_j] = chain_value[cnt_j];
            state[cnt_j] = chain_value[cnt_j];
        }
    }
    free(in);
}

void update(in_state *state, unsigned char *seed)
{
    int cnt_i, cnt_j, cnt_k = 0;
    unsigned char round_key[16 * 17] = {0x00};
    unsigned char result[16] = {
        0x00,
    };
    unsigned char temp[32] = {
        0x00,
    };

    for (cnt_i = 0; cnt_i < LEN_SEED; cnt_i++)
    {
        state->V[15]++;
        Crypt(state->V, EncKeySetup(state->key, round_key, 128), round_key, result);
        for (cnt_j = 0; cnt_j < BLOCK_SIZE; cnt_j++)
        {
            temp[cnt_i * 16 + cnt_j] = result[cnt_j];
        }
    }
    for (cnt_i = 0; cnt_i < 16; cnt_i++)
    {
        state->key[cnt_i] = temp[cnt_i] ^ seed[cnt_i];
        state->V[cnt_i] = temp[16 + cnt_i] ^ seed[16 + cnt_i];
    }
}

void gf(in_state *state, unsigned char *random, unsigned char *add_data, unsigned char *re_Entrophy, unsigned char *re_add_data,st_len* LEN)
{

    int cnt_i, cnt_j, cnt_k = 0;
    unsigned char round_key[16 * 17] = {0x00};
    unsigned char result[16] = {0x00};
    unsigned char a_data[16] = {0x00};
    unsigned char seed[32] = {0x00};
    unsigned char temp[32] = {0x00};

    if (state->prediction_flag == TRUE)
    {
        Reseed_Function(state,re_Entrophy,re_add_data,LEN);
        add_data = NULL;
        df(a_data, seed,&(LEN->general_len));
        for (cnt_i = 0; cnt_i < LEN_SEED; cnt_i++)
        {
            state->V[15]++;
            Crypt(state->V, EncKeySetup(state->key, round_key, 128), round_key, result);
            for (cnt_j = 0; cnt_j < BLOCK_SIZE; cnt_j++)
            {
                random[cnt_i * 16 + cnt_j] = result[cnt_j];
            }
        }

        for (cnt_i = 0; cnt_i < LEN_SEED; cnt_i++)
        {
            state->V[15]++;
            Crypt(state->V, EncKeySetup(state->key, round_key, 128), round_key, result);
            for (cnt_j = 0; cnt_j < BLOCK_SIZE; cnt_j++)
            {
                temp[cnt_i * 16 + cnt_j] = result[cnt_j];
            }
        }
        for (cnt_i = 0; cnt_i < 32; cnt_i++)
        {
            temp[cnt_i] ^= seed[cnt_i];
        }
        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            state->key[cnt_i] = temp[cnt_i] ^ seed[cnt_i];
            state->V[cnt_i] = temp[16 + cnt_i] ^ seed[16 + cnt_i];
        }
    }

    else if (add_data != NULL)
    {
        df(add_data, seed, &(LEN->general_len));
        update(state,seed);
        for (cnt_i = 0; cnt_i < LEN_SEED; cnt_i++)
        {
            state->V[15]++;
            Crypt(state->V, EncKeySetup(state->key, round_key, 128), round_key, result);
            for (cnt_j = 0; cnt_j < BLOCK_SIZE; cnt_j++)
            {
                random[cnt_i * 16 + cnt_j] = result[cnt_j];
            }
        }
        for (cnt_i = 0; cnt_i < LEN_SEED; cnt_i++)
        {
            state->V[15]++;
            Crypt(state->V, EncKeySetup(state->key, round_key, 128), round_key, result);
            for (cnt_j = 0; cnt_j < BLOCK_SIZE; cnt_j++)
            {
                temp[cnt_i * 16 + cnt_j] = result[cnt_j];
            }
        }
        for (cnt_i = 0; cnt_i < 32; cnt_i++)
        {
            temp[cnt_i] ^= seed[cnt_i];
        }
        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            state->key[cnt_i] = temp[cnt_i] ^ seed[cnt_i];
            state->V[cnt_i] = temp[16 + cnt_i] ^ seed[16 + cnt_i];
        }
    }

    else 
    {
        df(a_data, seed, &(LEN->general_len));
        for (cnt_i = 0; cnt_i < LEN_SEED; cnt_i++)
        {
            state->V[15]++;
            Crypt(state->V, EncKeySetup(state->key, round_key, 128), round_key, result);
            for (cnt_j = 0; cnt_j < BLOCK_SIZE; cnt_j++)
            {
                random[cnt_i * 16 + cnt_j] = result[cnt_j];
            }
        }

        for (cnt_i = 0; cnt_i < LEN_SEED; cnt_i++)
        {
            state->V[15]++;
            Crypt(state->V, EncKeySetup(state->key, round_key, 128), round_key, result);
            for (cnt_j = 0; cnt_j < BLOCK_SIZE; cnt_j++)
            {
                temp[cnt_i * 16 + cnt_j] = result[cnt_j];
            }
        }
        for (cnt_i = 0; cnt_i < 32; cnt_i++)
        {
            temp[cnt_i] ^= seed[cnt_i];
        }
        for (cnt_i = 0; cnt_i < 16; cnt_i++)
        {
            state->key[cnt_i] = temp[cnt_i] ^ seed[cnt_i];
            state->V[cnt_i] = temp[16 + cnt_i] ^ seed[16 + cnt_i];
        }
    }

    state->Reseed_counter++;
}

void Reseed_Function(in_state* state,unsigned char *re_Entrophy,unsigned char *re_add_data,st_len* len)
{
    int cnt_i = 0;
    unsigned char len2 = len->re_adddata + len->re_Entrophy;
    unsigned char *input_data = (unsigned char *)calloc(len2, sizeof(unsigned char));    
    unsigned char seed[32] = {0x00};
    for(cnt_i  = 0 ; cnt_i < len->re_Entrophy ; cnt_i ++)
    {
        input_data[cnt_i] = re_Entrophy[cnt_i];
    }
    for(cnt_i  = len->re_Entrophy ; cnt_i < len2 ; cnt_i ++)
    {
        input_data[cnt_i] = re_Entrophy[cnt_i - len->re_Entrophy];
    }

    df(input_data, seed, &len2);
    update(state,seed);
    free(input_data);

}

