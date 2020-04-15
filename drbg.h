/*
   brief CTR_DRBG based on AES-256 (NIST SP 800-90)
 
   Copyright (C) 2006-2014, ARM Limited, All Rights Reserved
 
   This file is part of mbed TLS (https://polarssl.org)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 
   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef CTR_DRBG_H
#define CTR_DRBG_H

#include <stdint.h>
#include <string.h>

#define UL64(x) x##ULL

#define EP_DRBG
//#define CTR_DRBG_SHA512

//CTR DEFINES
#define CTR_DRBG_BLOCKSIZE          16      //< Block size used by the cipher
#define CTR_DRBG_KEYSIZE            32      //< Key size used by the cipher
#define CTR_DRBG_KEYBITS            ( CTR_DRBG_KEYSIZE * 8 )
#define CTR_DRBG_SEEDLEN            ( CTR_DRBG_KEYSIZE + CTR_DRBG_BLOCKSIZE )//< The seed length (counter + AES key)

#define CTR_DRBG_RESEED_INTERVAL    10000   //< Interval before reseed is performed by default
#define CTR_DRBG_MAX_INPUT          256     //< Maximum number of additional input bytes
#define CTR_DRBG_MAX_REQUEST        1024    //< Maximum number of requested bytes per call
#define CTR_DRBG_MAX_SEED_INPUT     384     //< Maximum size of (re)seed buffer

#define CTR_DRBG_PR_OFF             0       //< No prediction resistance
#define CTR_DRBG_PR_ON              1       //< Prediction resistance enabled

//ENTROPY DEFINES
#if defined(CTR_DRBG_SHA512)
#define CTR_DRBG_ENTROPY_LEN        48      //< Amount of entropy used per seed by default (48 with SHA-512, 32 with SHA-256)
#define ENTROPY_BLOCK_SIZE      64      //< Block size of entropy accumulator (SHA-512)
#else
#define CTR_DRBG_ENTROPY_LEN        32      //< Amount of entropy used per seed by default (48 with SHA-512, 32 with SHA-256)
#define ENTROPY_BLOCK_SIZE      32      //< Block size of entropy accumulator (SHA-256)
#endif
#define ENTROPY_MAX_LOOP    256     //< Maximum amount to loop before error
#define ENTROPY_MAX_SOURCES 2
#define ENTROPY_MIN_PLATFORM    128
#define ENTROPY_MAX_GATHER      128     //< Maximum amount requested from entropy sources

//ERROR DEFINES
#define ERR_AES_INVALID_KEY_LENGTH                -0x0020  //Invalid key length.
#define ERR_AES_INVALID_INPUT_LENGTH              -0x0022  //Invalid data input length.
#define ERR_ENTROPY_SOURCE_FAILED                 -0x003C  //Critical entropy source failure.
#define ERR_ENTROPY_MAX_SOURCES                   -0x003E  //No more sources can be added.
#define ERR_ENTROPY_NO_SOURCES_DEFINED            -0x0040  //No sources have been added to poll.
#define ERR_ENTROPY_FILE_IO_ERROR                 -0x0058  //Read/write error in file.
#define ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED        -0x0034  //The entropy source failed.
#define ERR_CTR_DRBG_REQUEST_TOO_BIG              -0x0036  //Too many random requested in single call.
#define ERR_CTR_DRBG_INPUT_TOO_BIG                -0x0038  //Input too large (Entropy + additional).
#define ERR_CTR_DRBG_FILE_IO_ERROR                -0x003A  //Read/write error in file.
#define ERR_CTR_DRBG_CONTEXT_NULL				  -0x003C
#define ERR_CTR_DRBG_SELF_TEST_FAIL				  -0x003E
#define ERR_CTR_DRBG_ZEROIZE_FAIL				  -0x0041
#define ERR_CTR_DRBG_CATASTROPHIC_FAIL			  -0x0041

#define SELF_TEST_COUNTER			100 //this needs to be justified to meet NIST 800-90A 11.3.3
#define AES_ENCRYPT     1
#define AES_DECRYPT     0


// Platform-specific entropy poll callback
int platform_entropy_poll( void *data, unsigned char *output, size_t len, size_t *olen );
int stack_info_entropy_poll( void *data, unsigned char *output, size_t len, size_t *olen );

#ifndef EP_DRBG
typedef uint8_t ui8;
typedef uint32_t ui32;
typedef uint64_t ui64;
#endif
typedef uint32_t t_uint;

//brief           Entropy poll callback pointer
//param data      Callback-specific data pointer
//param output    Data to fill
//param len       Maximum size to provide
//param olen      The actual amount of bytes put into the buffer (Can be 0)
//return          0 if no critical failures occurred, ERR_ENTROPY_SOURCE_FAILED otherwise
typedef int (*f_source_ptr)(void *data, unsigned char *output, size_t len,
                            size_t *olen);

// Entropy source state
typedef struct
{
    f_source_ptr    f_source;   // The entropy source callback
    void *          p_source;   // The callback data pointer
    size_t          size;       // Amount received
    size_t          threshold;  // Minimum level required before release
}
source_state;

typedef struct
{
    int nr;                     //  number of rounds
    uint32_t *rk;               //  AES round keys
    uint32_t buf[68];           //  unaligned data
}
aes_context;

// CTR_DRBG context structure
typedef struct
{
    unsigned char counter[16];  //NIST 800-09A 10.2.1.1 - 1a
    int reseed_counter;         //NIST 800-09A 10.2.1.1 - 1c
    int prediction_resistance;  //NIST 800-09A 10.2.1.1 - 2b
    size_t entropy_len;         //NIST 800-09A 10.2.1.1 - 1b amount of entropy grabbed on each (re)seed
    int reseed_interval;        //reseed interval
    aes_context aes_ctx;        //AES context
    int (*f_entropy)(void *, unsigned char *, size_t);// Callbacks (Entropy)
    void *p_entropy;            //  context for the entropy function
}
ctr_drbg_context;

// SHA-256 context structure
typedef struct
{
    uint32_t total[2];          // number of bytes processed
    uint32_t state[8];          // intermediate digest state
    unsigned char buffer[64];   // data block being processed
    unsigned char ipad[64];     // HMAC: inner padding
    unsigned char opad[64];     // HMAC: outer padding
    int is224;                  // 0 => SHA-256, else SHA-224
}
sha256_context;

#if defined(CTR_DRBG_SHA512)
typedef struct
{
    uint64_t total[2];          //< number of bytes processed  
    uint64_t state[8];          //< intermediate digest state  
    unsigned char buffer[128];  //< data block being processed 
    unsigned char ipad[128];    //< HMAC: inner padding        
    unsigned char opad[128];    //< HMAC: outer padding        
    int is384;                  //< 0 => SHA-512, else SHA-384 
}
sha512_context;
#endif

// Entropy context structure
typedef struct
{
#if defined(CTR_DRBG_SHA512)
    sha512_context  accumulator;
#else
    sha256_context  accumulator;
#endif
    int             source_count;
    source_state    source[ENTROPY_MAX_SOURCES];
}
entropy_context;

int fRngDRBGGetRnd( unsigned char *pRnd);		// get a new RNG

//brief           Initialize the context
//param ctx       Entropy context to initialize
void entropy_init( entropy_context *ctx );

//brief           Retrieve entropy from the accumulator (Maximum length: ENTROPY_BLOCK_SIZE)
//param data      Entropy context
//param output    Buffer to fill
//param len       Number of bytes desired, must be at most ENTROPY_BLOCK_SIZE
//return          0 if successful, or ERR_ENTROPY_SOURCE_FAILED
int entropy_func( void *data, unsigned char *output, size_t len );

//brief           Adds an entropy source to poll
//param ctx       Entropy context
//param f_source  Entropy function
//param p_source  Function data
//param threshold Minimum required from source before entropy is released ( with entropy_func() )
//return          0 if successful or ERR_ENTROPY_MAX_SOURCES
int entropy_add_source( entropy_context *ctx, f_source_ptr f_source, void *p_source, size_t threshold );

void entropy_free( entropy_context *ctx );

//brief               CTR_DRBG initialization
//note: Personalization data can be provided in addition to the more generic
//     entropy source to make this instantiation as unique as possible.
//
//param ctx           CTR_DRBG context to be initialized
//param f_entropy     Entropy callback (p_entropy, buffer to fill, buffer length)
//param p_entropy     Entropy context
//param custom        Personalization data (Device specific identifiers) (Can be NULL)
//param len           Length of personalization data
//return              0 if successful, or ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED
int ctr_drbg_init( ctr_drbg_context *ctx, int (*f_entropy)(void *, unsigned char *, size_t),
                   void *p_entropy, const unsigned char *custom, size_t len );

//brief               Enable / disable prediction resistance (Default: Off)
//note: If enabled, entropy is used for ctx->entropy_len before each call!
//     Only use this if you have ample supply of good entropy!
//
//param ctx           CTR_DRBG context
//param resistance    CTR_DRBG_PR_ON or CTR_DRBG_PR_OFF
void ctr_drbg_set_prediction_resistance( ctr_drbg_context *ctx, int resistance );

//brief               Set the amount of entropy grabbed on each (re)seed (Default: CTR_DRBG_ENTROPY_LEN)
//param ctx           CTR_DRBG context
//param len           Amount of entropy to grab */
void ctr_drbg_set_entropy_len( ctr_drbg_context *ctx, size_t len );

//brief               Set the reseed interval
//                    (Default: CTR_DRBG_RESEED_INTERVAL)
//
//param ctx           CTR_DRBG context
//param interval      Reseed interval */
void ctr_drbg_set_reseed_interval( ctr_drbg_context *ctx, int interval );

//brief               CTR_DRBG reseeding (extracts data from entropy source)
//param ctx           CTR_DRBG context
//param additional    Additional data to add to state (Can be NULL)
//param len           Length of additional data
//return              0 if successful, or ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED
int ctr_drbg_reseed( ctr_drbg_context *ctx, const unsigned char *additional, size_t len );

//brief               CTR_DRBG update state
//param ctx           CTR_DRBG context
//param additional    Additional data to update state with
//param add_len       Length of additional data
//note                If add_len is greater than CTR_DRBG_MAX_SEED_INPUT, only the first CTR_DRBG_MAX_SEED_INPUT bytes are used,
//                    the remaining ones are silently discarded.
void ctr_drbg_update( ctr_drbg_context *ctx, const unsigned char *additional, size_t add_len );

//brief               CTR_DRBG generate random
//note: Automatically reseeds if reseed_counter is reached.
//param p_rng         CTR_DRBG context
//param output        Buffer to fill
//param output_len    Length of the buffer
//return              0 if successful, or ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED, or ERR_CTR_DRBG_REQUEST_TOO_BIG
int ctr_drbg_random( void *p_rng, unsigned char *output, size_t output_len );

//brief               CTR_DRBG generate random with additional update input
//note: Automatically reseeds if reseed_counter is reached.
//param p_rng         CTR_DRBG context
//param output        Buffer to fill
//param output_len    Length of the buffer
//param additional    Additional data to update with (Can be NULL)
//param add_len       Length of additional data
//return              0 if successful, or ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED, or ERR_CTR_DRBG_REQUEST_TOO_BIG
int ctr_drbg_random_with_add( void *p_rng, unsigned char *output, size_t output_len, const unsigned char *additional, size_t add_len );

//brief               Checkup routine
//return              0 if successful, or 1 if the test failed */
int ctr_drbg_self_test( int verbose );

//brief               Clear CTR_CRBG context data
//param ctx           CTR_DRBG context to clear
int ctr_drbg_free( ctr_drbg_context *ctx );

// Internal functions (do not call directly)
int ctr_drbg_init_entropy_len( ctr_drbg_context *, int (*)(void *, unsigned char *, size_t), void *,
                               const unsigned char *, size_t, size_t );

							   // Tables generation code
#define ROTL8(x) ( ( x << 8 ) & 0xFFFFFFFF ) | ( x >> 24 )
#define XTIME(x) ( ( x << 1 ) ^ ( ( x & 0x80 ) ? 0x1B : 0x00 ) )
#define MUL(x,y) ( ( x && y ) ? pow[(log[x]+log[y]) % 255] : 0 )

#define AES_FROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{                                               \
    X0 = *RK++ ^ FT0[ ( Y0       ) & 0xFF ] ^   \
                 FT1[ ( Y1 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y2 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y3 >> 24 ) & 0xFF ];    \
                                                \
    X1 = *RK++ ^ FT0[ ( Y1       ) & 0xFF ] ^   \
                 FT1[ ( Y2 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y3 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y0 >> 24 ) & 0xFF ];    \
                                                \
    X2 = *RK++ ^ FT0[ ( Y2       ) & 0xFF ] ^   \
                 FT1[ ( Y3 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y0 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y1 >> 24 ) & 0xFF ];    \
                                                \
    X3 = *RK++ ^ FT0[ ( Y3       ) & 0xFF ] ^   \
                 FT1[ ( Y0 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y1 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y2 >> 24 ) & 0xFF ];    \
}

#define AES_RROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{                                               \
    X0 = *RK++ ^ RT0[ ( Y0       ) & 0xFF ] ^   \
                 RT1[ ( Y3 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y2 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y1 >> 24 ) & 0xFF ];    \
                                                \
    X1 = *RK++ ^ RT0[ ( Y1       ) & 0xFF ] ^   \
                 RT1[ ( Y0 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y3 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y2 >> 24 ) & 0xFF ];    \
                                                \
    X2 = *RK++ ^ RT0[ ( Y2       ) & 0xFF ] ^   \
                 RT1[ ( Y1 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y0 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y3 >> 24 ) & 0xFF ];    \
                                                \
    X3 = *RK++ ^ RT0[ ( Y3       ) & 0xFF ] ^   \
                 RT1[ ( Y2 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y1 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y0 >> 24 ) & 0xFF ];    \
}

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

#ifndef GET_UINT32_LE
#define GET_UINT32_LE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ]       )             \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 2] << 16 )             \
        | ( (uint32_t) (b)[(i) + 3] << 24 );            \
}
#endif

#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n,b,i)                                    \
{                                                               \
    (b)[(i)    ] = (unsigned char) ( ( (n)       ) & 0xFF );    \
    (b)[(i) + 1] = (unsigned char) ( ( (n) >>  8 ) & 0xFF );    \
    (b)[(i) + 2] = (unsigned char) ( ( (n) >> 16 ) & 0xFF );    \
    (b)[(i) + 3] = (unsigned char) ( ( (n) >> 24 ) & 0xFF );    \
}
#endif

#define CHK( c )    if( (c) != 0 )                          \
                    {                                       \
                        if( verbose != 0 )                  \
                            printf( "failed\n" );			\
                            nDRBGSelfTestRunning = 0;		\
                        return( 1 );                        \
                    }
					
					#ifndef GET_UINT64_BE
#define GET_UINT64_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint64_t) (b)[(i)    ] << 56 )       \
        | ( (uint64_t) (b)[(i) + 1] << 48 )       \
        | ( (uint64_t) (b)[(i) + 2] << 40 )       \
        | ( (uint64_t) (b)[(i) + 3] << 32 )       \
        | ( (uint64_t) (b)[(i) + 4] << 24 )       \
        | ( (uint64_t) (b)[(i) + 5] << 16 )       \
        | ( (uint64_t) (b)[(i) + 6] <<  8 )       \
        | ( (uint64_t) (b)[(i) + 7]       );      \
}
#endif // GET_UINT64_BE

#ifndef PUT_UINT64_BE
#define PUT_UINT64_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 56 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 48 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >> 40 );       \
    (b)[(i) + 3] = (unsigned char) ( (n) >> 32 );       \
    (b)[(i) + 4] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 5] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 6] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 7] = (unsigned char) ( (n)       );       \
}
#endif // PUT_UINT64_BE
#endif // drbg.h */