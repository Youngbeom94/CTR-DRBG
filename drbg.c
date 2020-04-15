/*
 *  CTR_DRBG implementation based on AES-256 (NIST SP 800-90)
 *
 *  Copyright (C) 2006-2014, ARM Limited, All Rights Reserved
 *
 *  This modified file is part of mbed TLS (https://polarssl.org)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 *  The NIST SP 800-90 DRBGs are described in the following publucation.
 *
 *  http://csrc.nist.gov/publications/nistpubs/800-90/SP800-90revised_March2007.pdf
 */
#include "drbg.h"

#ifdef EP_DRBG 
#include <targetos.h>
//#include "timer.h"
#include <kprivate/kernelp.h>
#include <sys.h>
#include "typs.h"
// #include <sys/types.h>
// #include<sys/time.h>

#else
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <termios.h>
#include <inttypes.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/sha1.h>
#include <math.h>
#include <time.h>

#define DRBG_VERBOSE 0

static volatile int nRngDRBGInitOk = 0;
int nDRBGSelfTestRunning = 0;
ctr_drbg_context ctr_drbg;
entropy_context entropy;
static int aes_init_done = 0;
static size_t test_offset;

// Forward S-box & tables
static unsigned char FSb[256];
static uint32_t FT0[256];
static uint32_t FT1[256];
static uint32_t FT2[256];
static uint32_t FT3[256];

// Reverse S-box & tables
static unsigned char RSb[256];
static uint32_t RT0[256];
static uint32_t RT1[256];
static uint32_t RT2[256];
static uint32_t RT3[256];

// Round constants
static uint32_t RCON[10];

static const unsigned char sha256_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

#if defined(CTR_DRBG_SHA512)
static const unsigned char sha512_padding[128] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
#endif

static unsigned char entropy_source_pr[96] =
    { 0xc1, 0x80, 0x81, 0xa6, 0x5d, 0x44, 0x02, 0x16,
      0x19, 0xb3, 0xf1, 0x80, 0xb1, 0xc9, 0x20, 0x02,
      0x6a, 0x54, 0x6f, 0x0c, 0x70, 0x81, 0x49, 0x8b,
      0x6e, 0xa6, 0x62, 0x52, 0x6d, 0x51, 0xb1, 0xcb,
      0x58, 0x3b, 0xfa, 0xd5, 0x37, 0x5f, 0xfb, 0xc9,
      0xff, 0x46, 0xd2, 0x19, 0xc7, 0x22, 0x3e, 0x95,
      0x45, 0x9d, 0x82, 0xe1, 0xe7, 0x22, 0x9f, 0x63,
      0x31, 0x69, 0xd2, 0x6b, 0x57, 0x47, 0x4f, 0xa3,
      0x37, 0xc9, 0x98, 0x1c, 0x0b, 0xfb, 0x91, 0x31,
      0x4d, 0x55, 0xb9, 0xe9, 0x1c, 0x5a, 0x5e, 0xe4,
      0x93, 0x92, 0xcf, 0xc5, 0x23, 0x12, 0xd5, 0x56,
      0x2c, 0x4a, 0x6e, 0xff, 0xdc, 0x10, 0xd0, 0x68 };

static unsigned char entropy_source_nopr[64] =
    { 0x5a, 0x19, 0x4d, 0x5e, 0x2b, 0x31, 0x58, 0x14,
      0x54, 0xde, 0xf6, 0x75, 0xfb, 0x79, 0x58, 0xfe,
      0xc7, 0xdb, 0x87, 0x3e, 0x56, 0x89, 0xfc, 0x9d,
      0x03, 0x21, 0x7c, 0x68, 0xd8, 0x03, 0x38, 0x20,
      0xf9, 0xe6, 0x5e, 0x04, 0xd8, 0x56, 0xf3, 0xa9,
      0xc4, 0x4a, 0x4c, 0xbd, 0xc1, 0xd0, 0x08, 0x46,
      0xf5, 0x98, 0x3d, 0x77, 0x1c, 0x1b, 0x13, 0x7e,
      0x4e, 0x0f, 0x9d, 0x8e, 0xf4, 0x09, 0xf9, 0x2e };

static const unsigned char nonce_pers_pr[16] =
    { 0xd2, 0x54, 0xfc, 0xff, 0x02, 0x1e, 0x69, 0xd2,
      0x29, 0xc9, 0xcf, 0xad, 0x85, 0xfa, 0x48, 0x6c };

static const unsigned char nonce_pers_nopr[16] =
    { 0x1b, 0x54, 0xb8, 0xff, 0x06, 0x42, 0xbf, 0xf5,
      0x21, 0xf1, 0x5c, 0x1c, 0x0b, 0x66, 0x5f, 0x3f };

static const unsigned char result_pr[16] =
    { 0x34, 0x01, 0x16, 0x56, 0xb4, 0x29, 0x00, 0x8f,
      0x35, 0x63, 0xec, 0xb5, 0xf2, 0x59, 0x07, 0x23 };

static const unsigned char result_nopr[16] =
    { 0xa0, 0x54, 0x30, 0x3d, 0x8a, 0x7e, 0xa9, 0x88,
      0x9d, 0x90, 0x3e, 0x07, 0x7c, 0x6f, 0x21, 0x8f };

#if defined(CTR_DRBG_SHA512)
static unsigned char sha512_test_buf[3][113] =
{
    { "abc" },
    { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
      "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" },
    { "" }
};

static const int sha512_test_buflen[3] =
{
    3, 112, 1000
};

static const unsigned char sha512_test_sum[6][64] =
{
    // SHA-384 test vectors
    { 0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B,
      0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6, 0x50, 0x07,
      0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63,
      0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF, 0x5B, 0xED,
      0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23,
      0x58, 0xBA, 0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7 },
    { 0x09, 0x33, 0x0C, 0x33, 0xF7, 0x11, 0x47, 0xE8,
      0x3D, 0x19, 0x2F, 0xC7, 0x82, 0xCD, 0x1B, 0x47,
      0x53, 0x11, 0x1B, 0x17, 0x3B, 0x3B, 0x05, 0xD2,
      0x2F, 0xA0, 0x80, 0x86, 0xE3, 0xB0, 0xF7, 0x12,
      0xFC, 0xC7, 0xC7, 0x1A, 0x55, 0x7E, 0x2D, 0xB9,
      0x66, 0xC3, 0xE9, 0xFA, 0x91, 0x74, 0x60, 0x39 },
    { 0x9D, 0x0E, 0x18, 0x09, 0x71, 0x64, 0x74, 0xCB,
      0x08, 0x6E, 0x83, 0x4E, 0x31, 0x0A, 0x4A, 0x1C,
      0xED, 0x14, 0x9E, 0x9C, 0x00, 0xF2, 0x48, 0x52,
      0x79, 0x72, 0xCE, 0xC5, 0x70, 0x4C, 0x2A, 0x5B,
      0x07, 0xB8, 0xB3, 0xDC, 0x38, 0xEC, 0xC4, 0xEB,
      0xAE, 0x97, 0xDD, 0xD8, 0x7F, 0x3D, 0x89, 0x85 },

    // SHA-512 test vectors
    { 0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA,
      0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20, 0x41, 0x31,
      0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2,
      0x0A, 0x9E, 0xEE, 0xE6, 0x4B, 0x55, 0xD3, 0x9A,
      0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8,
      0x36, 0xBA, 0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD,
      0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E,
      0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F },
    { 0x8E, 0x95, 0x9B, 0x75, 0xDA, 0xE3, 0x13, 0xDA,
      0x8C, 0xF4, 0xF7, 0x28, 0x14, 0xFC, 0x14, 0x3F,
      0x8F, 0x77, 0x79, 0xC6, 0xEB, 0x9F, 0x7F, 0xA1,
      0x72, 0x99, 0xAE, 0xAD, 0xB6, 0x88, 0x90, 0x18,
      0x50, 0x1D, 0x28, 0x9E, 0x49, 0x00, 0xF7, 0xE4,
      0x33, 0x1B, 0x99, 0xDE, 0xC4, 0xB5, 0x43, 0x3A,
      0xC7, 0xD3, 0x29, 0xEE, 0xB6, 0xDD, 0x26, 0x54,
      0x5E, 0x96, 0xE5, 0x5B, 0x87, 0x4B, 0xE9, 0x09 },
    { 0xE7, 0x18, 0x48, 0x3D, 0x0C, 0xE7, 0x69, 0x64,
      0x4E, 0x2E, 0x42, 0xC7, 0xBC, 0x15, 0xB4, 0x63,
      0x8E, 0x1F, 0x98, 0xB1, 0x3B, 0x20, 0x44, 0x28,
      0x56, 0x32, 0xA8, 0x03, 0xAF, 0xA9, 0x73, 0xEB,
      0xDE, 0x0F, 0xF2, 0x44, 0x87, 0x7E, 0xA6, 0x0A,
      0x4C, 0xB0, 0x43, 0x2C, 0xE5, 0x77, 0xC3, 0x1B,
      0xEB, 0x00, 0x9C, 0x5C, 0x2C, 0x49, 0xAA, 0x2E,
      0x4E, 0xAD, 0xB2, 0x17, 0xAD, 0x8C, 0xC0, 0x9B }
};

// RFC 4231 test vectors
static unsigned char sha512_hmac_test_key[7][26] =
{
    { "\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B"
      "\x0B\x0B\x0B\x0B" },
    { "Jefe" },
    { "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
      "\xAA\xAA\xAA\xAA" },
    { "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
      "\x11\x12\x13\x14\x15\x16\x17\x18\x19" },
    { "\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C"
      "\x0C\x0C\x0C\x0C" },
    { "" }, /* 0xAA 131 times */
    { "" }
};

static const int sha512_hmac_test_keylen[7] =
{
    20, 4, 20, 25, 20, 131, 131
};

static unsigned char sha512_hmac_test_buf[7][153] =
{
    { "Hi There" },
    { "what do ya want for nothing?" },
    { "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
      "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
      "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
      "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
      "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD" },
    { "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
      "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
      "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
      "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
      "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD" },
    { "Test With Truncation" },
    { "Test Using Larger Than Block-Size Key - Hash Key First" },
    { "This is a test using a larger than block-size key "
      "and a larger than block-size data. The key needs to "
      "be hashed before being used by the HMAC algorithm." }
};

static const int sha512_hmac_test_buflen[7] =
{
    8, 28, 50, 50, 20, 54, 152
};

static const unsigned char sha512_hmac_test_sum[14][64] =
{
    /*
     * HMAC-SHA-384 test vectors
     */
    { 0xAF, 0xD0, 0x39, 0x44, 0xD8, 0x48, 0x95, 0x62,
      0x6B, 0x08, 0x25, 0xF4, 0xAB, 0x46, 0x90, 0x7F,
      0x15, 0xF9, 0xDA, 0xDB, 0xE4, 0x10, 0x1E, 0xC6,
      0x82, 0xAA, 0x03, 0x4C, 0x7C, 0xEB, 0xC5, 0x9C,
      0xFA, 0xEA, 0x9E, 0xA9, 0x07, 0x6E, 0xDE, 0x7F,
      0x4A, 0xF1, 0x52, 0xE8, 0xB2, 0xFA, 0x9C, 0xB6 },
    { 0xAF, 0x45, 0xD2, 0xE3, 0x76, 0x48, 0x40, 0x31,
      0x61, 0x7F, 0x78, 0xD2, 0xB5, 0x8A, 0x6B, 0x1B,
      0x9C, 0x7E, 0xF4, 0x64, 0xF5, 0xA0, 0x1B, 0x47,
      0xE4, 0x2E, 0xC3, 0x73, 0x63, 0x22, 0x44, 0x5E,
      0x8E, 0x22, 0x40, 0xCA, 0x5E, 0x69, 0xE2, 0xC7,
      0x8B, 0x32, 0x39, 0xEC, 0xFA, 0xB2, 0x16, 0x49 },
    { 0x88, 0x06, 0x26, 0x08, 0xD3, 0xE6, 0xAD, 0x8A,
      0x0A, 0xA2, 0xAC, 0xE0, 0x14, 0xC8, 0xA8, 0x6F,
      0x0A, 0xA6, 0x35, 0xD9, 0x47, 0xAC, 0x9F, 0xEB,
      0xE8, 0x3E, 0xF4, 0xE5, 0x59, 0x66, 0x14, 0x4B,
      0x2A, 0x5A, 0xB3, 0x9D, 0xC1, 0x38, 0x14, 0xB9,
      0x4E, 0x3A, 0xB6, 0xE1, 0x01, 0xA3, 0x4F, 0x27 },
    { 0x3E, 0x8A, 0x69, 0xB7, 0x78, 0x3C, 0x25, 0x85,
      0x19, 0x33, 0xAB, 0x62, 0x90, 0xAF, 0x6C, 0xA7,
      0x7A, 0x99, 0x81, 0x48, 0x08, 0x50, 0x00, 0x9C,
      0xC5, 0x57, 0x7C, 0x6E, 0x1F, 0x57, 0x3B, 0x4E,
      0x68, 0x01, 0xDD, 0x23, 0xC4, 0xA7, 0xD6, 0x79,
      0xCC, 0xF8, 0xA3, 0x86, 0xC6, 0x74, 0xCF, 0xFB },
    { 0x3A, 0xBF, 0x34, 0xC3, 0x50, 0x3B, 0x2A, 0x23,
      0xA4, 0x6E, 0xFC, 0x61, 0x9B, 0xAE, 0xF8, 0x97 },
    { 0x4E, 0xCE, 0x08, 0x44, 0x85, 0x81, 0x3E, 0x90,
      0x88, 0xD2, 0xC6, 0x3A, 0x04, 0x1B, 0xC5, 0xB4,
      0x4F, 0x9E, 0xF1, 0x01, 0x2A, 0x2B, 0x58, 0x8F,
      0x3C, 0xD1, 0x1F, 0x05, 0x03, 0x3A, 0xC4, 0xC6,
      0x0C, 0x2E, 0xF6, 0xAB, 0x40, 0x30, 0xFE, 0x82,
      0x96, 0x24, 0x8D, 0xF1, 0x63, 0xF4, 0x49, 0x52 },
    { 0x66, 0x17, 0x17, 0x8E, 0x94, 0x1F, 0x02, 0x0D,
      0x35, 0x1E, 0x2F, 0x25, 0x4E, 0x8F, 0xD3, 0x2C,
      0x60, 0x24, 0x20, 0xFE, 0xB0, 0xB8, 0xFB, 0x9A,
      0xDC, 0xCE, 0xBB, 0x82, 0x46, 0x1E, 0x99, 0xC5,
      0xA6, 0x78, 0xCC, 0x31, 0xE7, 0x99, 0x17, 0x6D,
      0x38, 0x60, 0xE6, 0x11, 0x0C, 0x46, 0x52, 0x3E },

    /*
     * HMAC-SHA-512 test vectors
     */
    { 0x87, 0xAA, 0x7C, 0xDE, 0xA5, 0xEF, 0x61, 0x9D,
      0x4F, 0xF0, 0xB4, 0x24, 0x1A, 0x1D, 0x6C, 0xB0,
      0x23, 0x79, 0xF4, 0xE2, 0xCE, 0x4E, 0xC2, 0x78,
      0x7A, 0xD0, 0xB3, 0x05, 0x45, 0xE1, 0x7C, 0xDE,
      0xDA, 0xA8, 0x33, 0xB7, 0xD6, 0xB8, 0xA7, 0x02,
      0x03, 0x8B, 0x27, 0x4E, 0xAE, 0xA3, 0xF4, 0xE4,
      0xBE, 0x9D, 0x91, 0x4E, 0xEB, 0x61, 0xF1, 0x70,
      0x2E, 0x69, 0x6C, 0x20, 0x3A, 0x12, 0x68, 0x54 },
    { 0x16, 0x4B, 0x7A, 0x7B, 0xFC, 0xF8, 0x19, 0xE2,
      0xE3, 0x95, 0xFB, 0xE7, 0x3B, 0x56, 0xE0, 0xA3,
      0x87, 0xBD, 0x64, 0x22, 0x2E, 0x83, 0x1F, 0xD6,
      0x10, 0x27, 0x0C, 0xD7, 0xEA, 0x25, 0x05, 0x54,
      0x97, 0x58, 0xBF, 0x75, 0xC0, 0x5A, 0x99, 0x4A,
      0x6D, 0x03, 0x4F, 0x65, 0xF8, 0xF0, 0xE6, 0xFD,
      0xCA, 0xEA, 0xB1, 0xA3, 0x4D, 0x4A, 0x6B, 0x4B,
      0x63, 0x6E, 0x07, 0x0A, 0x38, 0xBC, 0xE7, 0x37 },
    { 0xFA, 0x73, 0xB0, 0x08, 0x9D, 0x56, 0xA2, 0x84,
      0xEF, 0xB0, 0xF0, 0x75, 0x6C, 0x89, 0x0B, 0xE9,
      0xB1, 0xB5, 0xDB, 0xDD, 0x8E, 0xE8, 0x1A, 0x36,
      0x55, 0xF8, 0x3E, 0x33, 0xB2, 0x27, 0x9D, 0x39,
      0xBF, 0x3E, 0x84, 0x82, 0x79, 0xA7, 0x22, 0xC8,
      0x06, 0xB4, 0x85, 0xA4, 0x7E, 0x67, 0xC8, 0x07,
      0xB9, 0x46, 0xA3, 0x37, 0xBE, 0xE8, 0x94, 0x26,
      0x74, 0x27, 0x88, 0x59, 0xE1, 0x32, 0x92, 0xFB },
    { 0xB0, 0xBA, 0x46, 0x56, 0x37, 0x45, 0x8C, 0x69,
      0x90, 0xE5, 0xA8, 0xC5, 0xF6, 0x1D, 0x4A, 0xF7,
      0xE5, 0x76, 0xD9, 0x7F, 0xF9, 0x4B, 0x87, 0x2D,
      0xE7, 0x6F, 0x80, 0x50, 0x36, 0x1E, 0xE3, 0xDB,
      0xA9, 0x1C, 0xA5, 0xC1, 0x1A, 0xA2, 0x5E, 0xB4,
      0xD6, 0x79, 0x27, 0x5C, 0xC5, 0x78, 0x80, 0x63,
      0xA5, 0xF1, 0x97, 0x41, 0x12, 0x0C, 0x4F, 0x2D,
      0xE2, 0xAD, 0xEB, 0xEB, 0x10, 0xA2, 0x98, 0xDD },
    { 0x41, 0x5F, 0xAD, 0x62, 0x71, 0x58, 0x0A, 0x53,
      0x1D, 0x41, 0x79, 0xBC, 0x89, 0x1D, 0x87, 0xA6 },
    { 0x80, 0xB2, 0x42, 0x63, 0xC7, 0xC1, 0xA3, 0xEB,
      0xB7, 0x14, 0x93, 0xC1, 0xDD, 0x7B, 0xE8, 0xB4,
      0x9B, 0x46, 0xD1, 0xF4, 0x1B, 0x4A, 0xEE, 0xC1,
      0x12, 0x1B, 0x01, 0x37, 0x83, 0xF8, 0xF3, 0x52,
      0x6B, 0x56, 0xD0, 0x37, 0xE0, 0x5F, 0x25, 0x98,
      0xBD, 0x0F, 0xD2, 0x21, 0x5D, 0x6A, 0x1E, 0x52,
      0x95, 0xE6, 0x4F, 0x73, 0xF6, 0x3F, 0x0A, 0xEC,
      0x8B, 0x91, 0x5A, 0x98, 0x5D, 0x78, 0x65, 0x98 },
    { 0xE3, 0x7B, 0x6A, 0x77, 0x5D, 0xC8, 0x7D, 0xBA,
      0xA4, 0xDF, 0xA9, 0xF9, 0x6E, 0x5E, 0x3F, 0xFD,
      0xDE, 0xBD, 0x71, 0xF8, 0x86, 0x72, 0x89, 0x86,
      0x5D, 0xF5, 0xA3, 0x2D, 0x20, 0xCD, 0xC9, 0x44,
      0xB6, 0x02, 0x2C, 0xAC, 0x3C, 0x49, 0x82, 0xB1,
      0x0D, 0x5E, 0xEB, 0x55, 0xC3, 0xE4, 0xDE, 0x15,
      0x13, 0x46, 0x76, 0xFB, 0x6D, 0xE0, 0x44, 0x60,
      0x65, 0xC9, 0x74, 0x40, 0xFA, 0x8C, 0x6A, 0x58 }
};
#endif //endif for #if defined(CTR_DRBG_SHA512)

static const uint64_t K[80] =
{
    UL64(0x428A2F98D728AE22),  UL64(0x7137449123EF65CD),
    UL64(0xB5C0FBCFEC4D3B2F),  UL64(0xE9B5DBA58189DBBC),
    UL64(0x3956C25BF348B538),  UL64(0x59F111F1B605D019),
    UL64(0x923F82A4AF194F9B),  UL64(0xAB1C5ED5DA6D8118),
    UL64(0xD807AA98A3030242),  UL64(0x12835B0145706FBE),
    UL64(0x243185BE4EE4B28C),  UL64(0x550C7DC3D5FFB4E2),
    UL64(0x72BE5D74F27B896F),  UL64(0x80DEB1FE3B1696B1),
    UL64(0x9BDC06A725C71235),  UL64(0xC19BF174CF692694),
    UL64(0xE49B69C19EF14AD2),  UL64(0xEFBE4786384F25E3),
    UL64(0x0FC19DC68B8CD5B5),  UL64(0x240CA1CC77AC9C65),
    UL64(0x2DE92C6F592B0275),  UL64(0x4A7484AA6EA6E483),
    UL64(0x5CB0A9DCBD41FBD4),  UL64(0x76F988DA831153B5),
    UL64(0x983E5152EE66DFAB),  UL64(0xA831C66D2DB43210),
    UL64(0xB00327C898FB213F),  UL64(0xBF597FC7BEEF0EE4),
    UL64(0xC6E00BF33DA88FC2),  UL64(0xD5A79147930AA725),
    UL64(0x06CA6351E003826F),  UL64(0x142929670A0E6E70),
    UL64(0x27B70A8546D22FFC),  UL64(0x2E1B21385C26C926),
    UL64(0x4D2C6DFC5AC42AED),  UL64(0x53380D139D95B3DF),
    UL64(0x650A73548BAF63DE),  UL64(0x766A0ABB3C77B2A8),
    UL64(0x81C2C92E47EDAEE6),  UL64(0x92722C851482353B),
    UL64(0xA2BFE8A14CF10364),  UL64(0xA81A664BBC423001),
    UL64(0xC24B8B70D0F89791),  UL64(0xC76C51A30654BE30),
    UL64(0xD192E819D6EF5218),  UL64(0xD69906245565A910),
    UL64(0xF40E35855771202A),  UL64(0x106AA07032BBD1B8),
    UL64(0x19A4C116B8D2D0C8),  UL64(0x1E376C085141AB53),
    UL64(0x2748774CDF8EEB99),  UL64(0x34B0BCB5E19B48A8),
    UL64(0x391C0CB3C5C95A63),  UL64(0x4ED8AA4AE3418ACB),
    UL64(0x5B9CCA4F7763E373),  UL64(0x682E6FF3D6B2B8A3),
    UL64(0x748F82EE5DEFB2FC),  UL64(0x78A5636F43172F60),
    UL64(0x84C87814A1F0AB72),  UL64(0x8CC702081A6439EC),
    UL64(0x90BEFFFA23631E28),  UL64(0xA4506CEBDE82BDE9),
    UL64(0xBEF9A3F7B2C67915),  UL64(0xC67178F2E372532B),
    UL64(0xCA273ECEEA26619C),  UL64(0xD186B8C721C0C207),
    UL64(0xEADA7DD6CDE0EB1E),  UL64(0xF57D4F7FEE6ED178),
    UL64(0x06F067AA72176FBA),  UL64(0x0A637DC5A2C898A6),
    UL64(0x113F9804BEF90DAE),  UL64(0x1B710B35131C471B),
    UL64(0x28DB77F523047D84),  UL64(0x32CAAB7B40C72493),
    UL64(0x3C9EBE0A15C9BEBC),  UL64(0x431D67C49C100D4C),
    UL64(0x4CC5D4BECB3E42B6),  UL64(0x597F299CFC657E2A),
    UL64(0x5FCB6FAB3AD6FAEC),  UL64(0x6C44198C4A475817)
};

void sha256( const unsigned char *input, size_t ilen, unsigned char output[32], int is224 );
void sha256_init1( sha256_context *ctx );
void sha256_starts( sha256_context *ctx, int is224 );
void sha256_process1( sha256_context *ctx, const unsigned char data[64] );
void sha256_update( sha256_context *ctx, const unsigned char *input, size_t ilen );
void sha256_finish( sha256_context *ctx, unsigned char output[32] );
void sha256_free( sha256_context *ctx );

#if defined(CTR_DRBG_SHA512)
void sha512_init1( sha512_context *ctx );
void sha512_starts( sha512_context *ctx, int is384 );
void sha512_process1( sha512_context *ctx, const unsigned char data[128] );
void sha512_update( sha512_context *ctx, const unsigned char *input, size_t ilen );
void sha512_finish( sha512_context *ctx, unsigned char output[64] );
void sha512_free( sha512_context *ctx );
#endif

static void aes_gen_tables( void )
{
    int i, x, y, z;
    int pow[256], log[256];

    // compute pow and log tables over GF(2^8)
    for( i = 0, x = 1; i < 256; i++ )
    {
        pow[i] = x;
        log[x] = i;
        x = ( x ^ XTIME( x ) ) & 0xFF;
    }

    // calculate the round constants
    for( i = 0, x = 1; i < 10; i++ )
    {
        RCON[i] = (uint32_t) x;
        x = XTIME( x ) & 0xFF;
    }

    // generate the forward and reverse S-boxes
    FSb[0x00] = 0x63;
    RSb[0x63] = 0x00;

    for( i = 1; i < 256; i++ )
    {
        x = pow[255 - log[i]];

        y  = x; y = ( ( y << 1 ) | ( y >> 7 ) ) & 0xFF;
        x ^= y; y = ( ( y << 1 ) | ( y >> 7 ) ) & 0xFF;
        x ^= y; y = ( ( y << 1 ) | ( y >> 7 ) ) & 0xFF;
        x ^= y; y = ( ( y << 1 ) | ( y >> 7 ) ) & 0xFF;
        x ^= y ^ 0x63;

        FSb[i] = (unsigned char) x;
        RSb[x] = (unsigned char) i;
    }

    // generate the forward and reverse tables
    for( i = 0; i < 256; i++ )
    {
        x = FSb[i];
        y = XTIME( x ) & 0xFF;
        z =  ( y ^ x ) & 0xFF;

        FT0[i] = ( (uint32_t) y       ) ^
                 ( (uint32_t) x <<  8 ) ^
                 ( (uint32_t) x << 16 ) ^
                 ( (uint32_t) z << 24 );

        FT1[i] = ROTL8( FT0[i] );
        FT2[i] = ROTL8( FT1[i] );
        FT3[i] = ROTL8( FT2[i] );

        x = RSb[i];

        RT0[i] = ( (uint32_t) MUL( 0x0E, x )       ) ^
                 ( (uint32_t) MUL( 0x09, x ) <<  8 ) ^
                 ( (uint32_t) MUL( 0x0D, x ) << 16 ) ^
                 ( (uint32_t) MUL( 0x0B, x ) << 24 );

        RT1[i] = ROTL8( RT0[i] );
        RT2[i] = ROTL8( RT1[i] );
        RT3[i] = ROTL8( RT2[i] );
    }
}

int aes_crypt_ecb( aes_context *ctx, int mode, const unsigned char input[16], unsigned char output[16] )
{
    int i;
    uint32_t *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;

    RK = ctx->rk;

    GET_UINT32_LE( X0, input,  0 ); X0 ^= *RK++;
    GET_UINT32_LE( X1, input,  4 ); X1 ^= *RK++;
    GET_UINT32_LE( X2, input,  8 ); X2 ^= *RK++;
    GET_UINT32_LE( X3, input, 12 ); X3 ^= *RK++;

    if( mode == AES_DECRYPT )
    {
        for( i = ( ctx->nr >> 1 ) - 1; i > 0; i-- )
        {
            AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );
            AES_RROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );
        }

        AES_RROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );

        X0 = *RK++ ^ \
                ( (uint32_t) RSb[ ( Y0       ) & 0xFF ]       ) ^
                ( (uint32_t) RSb[ ( Y3 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) RSb[ ( Y2 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) RSb[ ( Y1 >> 24 ) & 0xFF ] << 24 );

        X1 = *RK++ ^ \
                ( (uint32_t) RSb[ ( Y1       ) & 0xFF ]       ) ^
                ( (uint32_t) RSb[ ( Y0 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) RSb[ ( Y3 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) RSb[ ( Y2 >> 24 ) & 0xFF ] << 24 );

        X2 = *RK++ ^ \
                ( (uint32_t) RSb[ ( Y2       ) & 0xFF ]       ) ^
                ( (uint32_t) RSb[ ( Y1 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) RSb[ ( Y0 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) RSb[ ( Y3 >> 24 ) & 0xFF ] << 24 );

        X3 = *RK++ ^ \
                ( (uint32_t) RSb[ ( Y3       ) & 0xFF ]       ) ^
                ( (uint32_t) RSb[ ( Y2 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) RSb[ ( Y1 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) RSb[ ( Y0 >> 24 ) & 0xFF ] << 24 );
    }
    else // AES_ENCRYPT
    {
        for( i = ( ctx->nr >> 1 ) - 1; i > 0; i-- )
        {
            AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );
            AES_FROUND( X0, X1, X2, X3, Y0, Y1, Y2, Y3 );
        }

        AES_FROUND( Y0, Y1, Y2, Y3, X0, X1, X2, X3 );

        X0 = *RK++ ^ \
                ( (uint32_t) FSb[ ( Y0       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( Y1 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( Y2 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( Y3 >> 24 ) & 0xFF ] << 24 );

        X1 = *RK++ ^ \
                ( (uint32_t) FSb[ ( Y1       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( Y2 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( Y3 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( Y0 >> 24 ) & 0xFF ] << 24 );

        X2 = *RK++ ^ \
                ( (uint32_t) FSb[ ( Y2       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( Y3 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( Y0 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( Y1 >> 24 ) & 0xFF ] << 24 );

        X3 = *RK++ ^ \
                ( (uint32_t) FSb[ ( Y3       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( Y0 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( Y1 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( Y2 >> 24 ) & 0xFF ] << 24 );
    }

    PUT_UINT32_LE( X0, output,  0 );
    PUT_UINT32_LE( X1, output,  4 );
    PUT_UINT32_LE( X2, output,  8 );
    PUT_UINT32_LE( X3, output, 12 );

    return( 0 );
}

//START NIST 800-90A 9.4///////////////////////////////////////////////////////////////////////////////////////////
// Implementation that should never be optimized out by the compiler
//was static void mercury_zeroize( void *v, size_t n ) {
static void mercury_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

int aes_free( aes_context *ctx )
{
    if( ctx == NULL )
        return ERR_CTR_DRBG_CONTEXT_NULL;
    mercury_zeroize( ctx, sizeof( aes_context ) );

    return 0;
}

//NIST 800-90A 9.4
//Remove a DRGB Instantiation
//release/zeroize contents of the internal state
//Uninstantiate_function
//--> 1) state_handle: *ctx
//Output
//--> 1) status: None
//was void ctr_drbg_free( ctr_drbg_context *ctx )
int ctr_drbg_free( ctr_drbg_context *ctx )
{
    if( ctx == NULL )
        return ERR_CTR_DRBG_CONTEXT_NULL;

    if(aes_free( &ctx->aes_ctx )) {
    	return ERR_CTR_DRBG_CONTEXT_NULL;
    }
    mercury_zeroize( ctx, sizeof( ctr_drbg_context ) );

    return 0;
}
//END NIST 800-90A 9.4///////////////////////////////////////////////////////////////////////////////////////////

void aes_init( aes_context *ctx )
{
    memset( ctx, 0, sizeof( aes_context ) );
}

//AES key schedule (encryption)
int aes_setkey_enc( aes_context *ctx, const unsigned char *key, unsigned int keysize )
{
    unsigned int i;
    uint32_t *RK;

    if( aes_init_done == 0 )
    {
        aes_gen_tables();
        aes_init_done = 1;

    }

    switch( keysize )
    {
        case 128: ctx->nr = 10; break;
        case 192: ctx->nr = 12; break;
        case 256: ctx->nr = 14; break;
        default : return( ERR_AES_INVALID_KEY_LENGTH );
    }

    ctx->rk = RK = ctx->buf;

    for( i = 0; i < ( keysize >> 5 ); i++ )
    {
        GET_UINT32_LE( RK[i], key, i << 2 );
    }

    switch( ctx->nr )
    {
        case 10:

            for( i = 0; i < 10; i++, RK += 4 )
            {
                RK[4]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[3] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[3] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[3] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[3]       ) & 0xFF ] << 24 );

                RK[5]  = RK[1] ^ RK[4];
                RK[6]  = RK[2] ^ RK[5];
                RK[7]  = RK[3] ^ RK[6];
            }
            break;

        case 12:

            for( i = 0; i < 8; i++, RK += 6 )
            {
                RK[6]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[5] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[5] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[5] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[5]       ) & 0xFF ] << 24 );

                RK[7]  = RK[1] ^ RK[6];
                RK[8]  = RK[2] ^ RK[7];
                RK[9]  = RK[3] ^ RK[8];
                RK[10] = RK[4] ^ RK[9];
                RK[11] = RK[5] ^ RK[10];
            }
            break;

        case 14:

            for( i = 0; i < 7; i++, RK += 8 )
            {
                RK[8]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( RK[7] >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[7] >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[7] >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[7]       ) & 0xFF ] << 24 );

                RK[9]  = RK[1] ^ RK[8];
                RK[10] = RK[2] ^ RK[9];
                RK[11] = RK[3] ^ RK[10];

                RK[12] = RK[4] ^
                ( (uint32_t) FSb[ ( RK[11]       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( RK[11] >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( RK[11] >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( RK[11] >> 24 ) & 0xFF ] << 24 );

                RK[13] = RK[5] ^ RK[12];
                RK[14] = RK[6] ^ RK[13];
                RK[15] = RK[7] ^ RK[14];
            }
            break;
    }

    return( 0 );
}

// AES key schedule (decryption)
int aes_setkey_dec( aes_context *ctx, const unsigned char *key,
                    unsigned int keysize )
{
    int i, j, ret;
    aes_context cty;
    uint32_t *RK;
    uint32_t *SK;

    aes_init( &cty );

    ctx->rk = RK = ctx->buf;

    // Also checks keysize
    if( ( ret = aes_setkey_enc( &cty, key, keysize ) ) != 0 )
        goto exit;

    ctx->nr = cty.nr;

    SK = cty.rk + cty.nr * 4;

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;

    for( i = ctx->nr - 1, SK -= 8; i > 0; i--, SK -= 8 )
    {
        for( j = 0; j < 4; j++, SK++ )
        {
            *RK++ = RT0[ FSb[ ( *SK       ) & 0xFF ] ] ^
                    RT1[ FSb[ ( *SK >>  8 ) & 0xFF ] ] ^
                    RT2[ FSb[ ( *SK >> 16 ) & 0xFF ] ] ^
                    RT3[ FSb[ ( *SK >> 24 ) & 0xFF ] ];
        }
    }

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;

exit:
    aes_free( &cty );

    return( ret );
}

//NIST 800-90A 10.4.2
//Derivation Function to derive the requested number of bits
//Block_Cipher_df
//--> 1) input_string: *data
//--> 2) no_of_bits_to_return: data_len
//Output
//--> 1) status: return value
//--> 2) requested_bits: *output
static int block_cipher_df( unsigned char *output, const unsigned char *data, size_t data_len )
{
    unsigned char buf[CTR_DRBG_MAX_SEED_INPUT + CTR_DRBG_BLOCKSIZE + 16];
    unsigned char tmp[CTR_DRBG_SEEDLEN];
    unsigned char key[CTR_DRBG_KEYSIZE];
    unsigned char chain[CTR_DRBG_BLOCKSIZE];
    unsigned char *p, *iv;
    aes_context aes_ctx;

    int i, j;
    size_t buf_len, use_len;

    if( data_len > CTR_DRBG_MAX_SEED_INPUT )
        return( ERR_CTR_DRBG_INPUT_TOO_BIG );

    memset( buf, 0, CTR_DRBG_MAX_SEED_INPUT + CTR_DRBG_BLOCKSIZE + 16 );
    aes_init( &aes_ctx );


    // Construct IV (16 bytes) and S in buffer
    // IV = Counter (in 32-bits) padded to 16 with zeroes
    // S = Length input string (in 32-bits) || Length of output (in 32-bits) || data || 0x80
    //     (Total is padded to a multiple of 16-bytes with zeroes)
    p = buf + CTR_DRBG_BLOCKSIZE;
    *p++ = ( data_len >> 24 ) & 0xff;
    *p++ = ( data_len >> 16 ) & 0xff;
    *p++ = ( data_len >> 8  ) & 0xff;
    *p++ = ( data_len       ) & 0xff;
    p += 3;
    *p++ = CTR_DRBG_SEEDLEN;
    memcpy( p, data, data_len );
    p[data_len] = 0x80;

    buf_len = CTR_DRBG_BLOCKSIZE + 8 + data_len + 1;

    for( i = 0; i < CTR_DRBG_KEYSIZE; i++ )
        key[i] = i;

    aes_setkey_enc( &aes_ctx, key, CTR_DRBG_KEYBITS );

    // Reduce data to CTR_DRBG_SEEDLEN bytes of data
    for( j = 0; j < CTR_DRBG_SEEDLEN; j += CTR_DRBG_BLOCKSIZE )
    {
        p = buf;
        memset( chain, 0, CTR_DRBG_BLOCKSIZE );
        use_len = buf_len;

        while( use_len > 0 )
        {
            for( i = 0; i < CTR_DRBG_BLOCKSIZE; i++ )
                chain[i] ^= p[i];
            p += CTR_DRBG_BLOCKSIZE;
            use_len -= ( use_len >= CTR_DRBG_BLOCKSIZE ) ?
                       CTR_DRBG_BLOCKSIZE : use_len;

            aes_crypt_ecb( &aes_ctx, AES_ENCRYPT, chain, chain );
        }

        memcpy( tmp + j, chain, CTR_DRBG_BLOCKSIZE );

        // Update IV
        buf[3]++;
    }

    // Do final encryption with reduced data
    aes_setkey_enc( &aes_ctx, tmp, CTR_DRBG_KEYBITS );
    iv = tmp + CTR_DRBG_KEYSIZE;
    p = output;

    for( j = 0; j < CTR_DRBG_SEEDLEN; j += CTR_DRBG_BLOCKSIZE )
    {
        aes_crypt_ecb( &aes_ctx, AES_ENCRYPT, iv, iv );
        memcpy( p, iv, CTR_DRBG_BLOCKSIZE );
        p += CTR_DRBG_BLOCKSIZE;
    }

    aes_free( &aes_ctx );

    return( 0 );
}

// Non-public function wrapped by ctr_crbg_init(). Necessary to allow NIST
// tests to succeed (which require known length fixed entropy)
//NIST 800-90A 9.1
int ctr_drbg_init_entropy_len(ctr_drbg_context *ctx, int (*f_entropy)(void *, unsigned char *, size_t),
                   void *p_entropy, const unsigned char *custom, size_t len, size_t entropy_len )
{
    int ret;
    unsigned char key[CTR_DRBG_KEYSIZE];

    memset( ctx, 0, sizeof(ctr_drbg_context) );
    memset( key, 0, CTR_DRBG_KEYSIZE );

    //need to check inputs here - satisfy
    if(ctx == NULL)
    	return ERR_CTR_DRBG_CONTEXT_NULL;
    if((p_entropy == NULL) || (f_entropy == NULL))
    	return ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;

    aes_init( &ctx->aes_ctx );

    ctx->f_entropy = f_entropy;
    ctx->p_entropy = p_entropy;

    ctx->entropy_len = entropy_len;
    ctx->reseed_interval = CTR_DRBG_RESEED_INTERVAL;

    // Initialize with an empty key
    aes_setkey_enc( &ctx->aes_ctx, key, CTR_DRBG_KEYBITS );

    if( ( ret = ctr_drbg_reseed( ctx, custom, len ) ) != 0 )
        return( ret );

    return( 0 );
}

//NIST 800-90A 10.2.1.3, NIST 800-90A 9.1
int ctr_drbg_init( ctr_drbg_context *ctx, int (*f_entropy)(void *, unsigned char *, size_t),
                   void *p_entropy, const unsigned char *custom, size_t len )
{
	nRngDRBGInitOk = 1;
    return(ctr_drbg_init_entropy_len( ctx, f_entropy, p_entropy, custom, len, CTR_DRBG_ENTROPY_LEN));
}

void ctr_drbg_set_prediction_resistance( ctr_drbg_context *ctx, int resistance )
{
    ctx->prediction_resistance = resistance;
}

void ctr_drbg_set_entropy_len( ctr_drbg_context *ctx, size_t len )
{
    ctx->entropy_len = len;
}

void ctr_drbg_set_reseed_interval( ctr_drbg_context *ctx, int interval )
{
    ctx->reseed_interval = interval;
}

//NIST 800-90A 10.2.1.2
//Update the internal state of ctr_drbg_context using data
//Use the block cipher algorithm aes_crypt_ecb
//CTR_DRBG_UPDATE
//--> 1) provided_data: data[CTR_DRBG_SEEDLEN]
//--> 2) Key: ctx->aes_ctx
//--> 3) V: ctx->counter
//Output
//--> 1) Key: ctx->aes_ctx
//--> 2) V: ctx->counter
static int ctr_drbg_update_internal( ctr_drbg_context *ctx, const unsigned char data[CTR_DRBG_SEEDLEN] )
{
    unsigned char tmp[CTR_DRBG_SEEDLEN];
    unsigned char *p = tmp;
    int i, j;

    //CTR_DRBG_Update Process step 1
    memset( tmp, 0, CTR_DRBG_SEEDLEN );

    //CTR_DRBG_Update Process step 2
    for( j = 0; j < CTR_DRBG_SEEDLEN; j += CTR_DRBG_BLOCKSIZE )
    {
        // Increase counter
        for( i = CTR_DRBG_BLOCKSIZE; i > 0; i-- )
            if( ++ctx->counter[i - 1] != 0 )
                break;

        // Crypt counter block
        aes_crypt_ecb( &ctx->aes_ctx, AES_ENCRYPT, ctx->counter, p );

        p += CTR_DRBG_BLOCKSIZE;
    }

    for( i = 0; i < CTR_DRBG_SEEDLEN; i++ )
    	//CTR_DRBG_Update Process step 4
        tmp[i] ^= data[i];

    // Update key and counter
    //CTR_DRBG_Update Process step 5
    aes_setkey_enc( &ctx->aes_ctx, tmp, CTR_DRBG_KEYBITS );
    //CTR_DRBG_Update Process step 6
    memcpy( ctx->counter, tmp + CTR_DRBG_KEYSIZE, CTR_DRBG_BLOCKSIZE );
    //CTR_DRBG_Update Process step 7
    return( 0 );
}

void ctr_drbg_update( ctr_drbg_context *ctx, const unsigned char *additional, size_t add_len )
{
    unsigned char add_input[CTR_DRBG_SEEDLEN];

    if( add_len > 0 )
    {
        // MAX_INPUT would be more logical here, but we have to match
        // block_cipher_df()'s limits since we can't propagate errors
        if( add_len > CTR_DRBG_MAX_SEED_INPUT )
            add_len = CTR_DRBG_MAX_SEED_INPUT;

        block_cipher_df( add_input, additional, add_len );
        ctr_drbg_update_internal( ctx, add_input );
    }
}

//NIST 800-90A 10.2.1.4.2, NIST 800-90A 9.2
//Reseeding with a Derivation Function
//CTR_DRBG_Generate_algorithm
//--> 1) working_state: *ctx
//--> 2) entropy_intput: *ctx->aes_ctx
//--> 3) additional_input: *additional
//Output
//--> 1) new_working_state: *ctx
int ctr_drbg_reseed( ctr_drbg_context *ctx, const unsigned char *additional, size_t len )
{
    unsigned char seed[CTR_DRBG_MAX_SEED_INPUT];
    size_t seedlen = 0;

    //NIST 800-90A 11.3.4
    if(!nDRBGSelfTestRunning) {
		if(ctr_drbg_self_test(DRBG_VERBOSE))
			return ERR_CTR_DRBG_SELF_TEST_FAIL;
    }

    if( ctx->entropy_len + len > CTR_DRBG_MAX_SEED_INPUT )
        return( ERR_CTR_DRBG_INPUT_TOO_BIG );

    memset( seed, 0, CTR_DRBG_MAX_SEED_INPUT );

    // Gather entropy_len bytes of entropy to seed state
    if( 0 != ctx->f_entropy( ctx->p_entropy, seed, ctx->entropy_len))
    {
        return( ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED );
    }

    seedlen += ctx->entropy_len;

    // Add additional data
    //CTR_DRBG Reseed Process step 1
    if( additional && len )
    {
        memcpy( seed + seedlen, additional, len );
        seedlen += len;
    }

    // Reduce to 384 bits
    //CTR_DRBG Reseed Process step 2
    block_cipher_df( seed, seed, seedlen );

    //CTR_DRBG Reseed Process step 3
    ctr_drbg_update_internal( ctx, seed );

    //CTR_DRBG Reseed Process step 4
    ctx->reseed_counter = 1;

    //CTR_DRBG Reseed Process step 5
    return( 0 );
}

//NIST 800-90A 10.2.1.5.2, NIST 800-90A 9.3.1
//Generate Pseudorandom bits with a Derivation Function
//CTR_DRBG_Generate_algorithm
//--> 1) working_state: *p_rng
//--> 2) requested_number_of_bits: output_len
//--> 3) additional_input: *additional
//Output
//--> 1) status: return status
//--> 2) returned_bits: *output
//--> 3) working_state: *p_rng(aes_ctx, reseed_counter
int ctr_drbg_random_with_add( void *p_rng, unsigned char *output, size_t output_len, const unsigned char *additional, size_t add_len )
{
    int ret = 0;
    ctr_drbg_context *ctx = (ctr_drbg_context *) p_rng;
    unsigned char add_input[CTR_DRBG_SEEDLEN];
    unsigned char *p = output;
    unsigned char tmp[CTR_DRBG_BLOCKSIZE];
    int i;
    size_t use_len;

    if( output_len > CTR_DRBG_MAX_REQUEST )
        return( ERR_CTR_DRBG_REQUEST_TOO_BIG );

    if( add_len > CTR_DRBG_MAX_INPUT )
        return( ERR_CTR_DRBG_INPUT_TOO_BIG );

    memset( add_input, 0, CTR_DRBG_SEEDLEN );

    //CTR_DRBG Generate Process step 1, NIST 800-90A 9.3.2
    if( ctx->reseed_counter > ctx->reseed_interval || ctx->prediction_resistance )
    {
        if( ( ret = ctr_drbg_reseed( ctx, additional, add_len ) ) != 0 )
            return( ret );

        add_len = 0;
    }

    //CTR_DRBG Generate Process step 2
    if( add_len > 0 )
    {
    	//CTR_DRBG Generate Process step 2.1
        block_cipher_df( add_input, additional, add_len );
        //CTR_DRBG Generate Process step 2.2
        ctr_drbg_update_internal( ctx, add_input );
    }

    //CTR_DRBG Generate Process step 4
    while( output_len > 0 )
    {
        // Increase counter
        for( i = CTR_DRBG_BLOCKSIZE; i > 0; i-- )
            if( ++ctx->counter[i - 1] != 0 )
                break;

        // Crypt counter block
        aes_crypt_ecb( &ctx->aes_ctx, AES_ENCRYPT, ctx->counter, tmp );

        use_len = ( output_len > CTR_DRBG_BLOCKSIZE ) ? CTR_DRBG_BLOCKSIZE : output_len;
        // Copy random block to destination
        //CTR_DRBG Generate Process step 5
        memcpy( p, tmp, use_len );
        p += use_len;
        output_len -= use_len;
    }

    //CTR_DRBG Generate Process step 6
    ctr_drbg_update_internal( ctx, add_input );

    //CTR_DRBG Generate Process step 7
    ctx->reseed_counter++;

    //CTR_DRBG Generate Process step 8
    return( 0 );
}

//NIST 800-90A 10.2.1.5
int ctr_drbg_random( void *p_rng, unsigned char *output, size_t output_len )
{
    return ctr_drbg_random_with_add( p_rng, output, output_len, NULL, 0 );
}

static int ctr_drbg_self_test_entropy( void *data, unsigned char *buf, size_t len )
{
    const unsigned char *p = data;
    memcpy( buf, p + test_offset, len );
    test_offset += len;
    return( 0 );
}

static int ctr_drbg_self_test_entropy_fail( void *data, unsigned char *buf, size_t len )
{
    return( ERR_ENTROPY_SOURCE_FAILED );
}

//NIST 800-90A 11.3, NIST 800-90A 11.3.1
//Health Testing
//Known Answer Testing
int ctr_drbg_self_test( int verbose )
{
    ctr_drbg_context ctx;
    unsigned char buf[16];
    char cAdditionalText = 'X';

    // Based on a NIST CTR_DRBG test vector (PR = FALSE)
    if( verbose != 0 )
        printf( "  CTR_DRBG (PR = FALSE): \n" );

    test_offset = 0;
    nDRBGSelfTestRunning = 1;
#ifdef CTR_DRBG_SHA512
    if( ( sha512_self_test( VERBOSE ) ) != 0 )
            return ERR_CTR_DRBG_SELF_TEST_FAIL;
#endif
    //NIST 800-09A 11.3.2 - Failed Entropy Input
    if(ctr_drbg_init_entropy_len( &ctx, ctr_drbg_self_test_entropy_fail, entropy_source_nopr, nonce_pers_nopr, 16, 32)  != ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED)
    	return ERR_CTR_DRBG_SELF_TEST_FAIL;

    //NIST 800-90A 11.3.4 - Error checking
	if(ctr_drbg_reseed( &ctx, buf, 16) != ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED)
			return ERR_CTR_DRBG_SELF_TEST_FAIL;

    //NIST 800-90A 11.3.2 - Valid Entropy Input
    CHK(ctr_drbg_init_entropy_len( &ctx, ctr_drbg_self_test_entropy, entropy_source_nopr, nonce_pers_nopr, 16, 32 ));
    //NIST 800-90A 11.3.3
    CHK(ctr_drbg_random( &ctx, buf, 16));
    //NIST 800-90A 11.3.3 - Reseed counter exceeded
    ctx.reseed_counter = ctx.reseed_interval + 1;
    //NIST 800-90A 11.3.3
    CHK(ctr_drbg_random( &ctx, buf, 16));
    CHK(memcmp( buf, result_nopr, 16 ));

    //NIST 800-90A 11.3.4 - Error checking
    if(ctr_drbg_reseed( &ctx, cAdditionalText, CTR_DRBG_MAX_SEED_INPUT) != ERR_CTR_DRBG_INPUT_TOO_BIG)
        	return ERR_CTR_DRBG_SELF_TEST_FAIL;

    //NIST 800-90A 11.3.5 - Verify error handling
    if(!ctr_drbg_free(NULL) == ERR_CTR_DRBG_CONTEXT_NULL)
    	return 1;

    //NIST 800-90A 11.3.5 - Verify internal state is zeroized
    CHK( ctr_drbg_free( &ctx ));
    unsigned char *p = &ctx;
    int n = sizeof(ctx);
    while( n-- ) {
    	if(*p != 0)
    	return ERR_CTR_DRBG_ZEROIZE_FAIL;
	}

    if( verbose != 0 )
        printf( "Self Tests passed\n" );

    nDRBGSelfTestRunning = 0;
    return(0);
}

//NIST 800-90A 8.6.X
//Generate Pseudorandom bits with a Derivation Function
//CTR_DRBG_Generate_algorithm
//--> 1) working_state: *p_rng
//--> 2) requested_number_of_bits: output_len
//--> 3) additional_input: *additional
//Output
//--> 1) status: return status
//--> 2) returned_bits: *output
//--> 3) working_state: *p_rng(aes_ctx, reseed_counter
void entropy_init( entropy_context *ctx )
{
    memset( ctx, 0, sizeof(entropy_context) );

#ifdef CTR_DRBG_SHA512
    sha512_starts( &ctx->accumulator, 0 );
#else
    sha256_starts( &ctx->accumulator, 0 );
#endif

    entropy_add_source( ctx, platform_entropy_poll, NULL, ENTROPY_MIN_PLATFORM );
#ifdef EP_DRBG
    entropy_add_source( ctx, stack_info_entropy_poll, NULL, ENTROPY_MIN_PLATFORM );
#endif
}

//NIST 800-90A 8.6.X
//Generate Pseudorandom bits with a Derivation Function
//CTR_DRBG_Generate_algorithm
//--> 1) working_state: *p_rng
//--> 2) requested_number_of_bits: output_len
//--> 3) additional_input: *additional
//Output
//--> 1) status: return status
//--> 2) returned_bits: *output
//--> 3) working_state: *p_rng(aes_ctx, reseed_counter
int platform_entropy_poll( void *data, unsigned char *output, size_t len, size_t *olen )
{
    ((void) data);

    *olen = 0;
#ifdef EP_DRBG
	srand(SysCounter());	// initialize the seed using 32-bit timer
	int i;
	for(i = 0; i<8; i++) {
		output = ((ui16)rand() << 48) | ((ui16)rand() << 32) | ((ui16)rand() << 16) | ((ui16)rand() + 1);
	}
	len = 64;
#else
	FILE *file;
    size_t ret;
    file = fopen( "/dev/urandom", "rb" );
    if( file == NULL )
        return( ERR_ENTROPY_SOURCE_FAILED );

    ret = fread( output, 1, len, file );
    if( ret != len )
    {
        fclose( file );
        return( ERR_ENTROPY_SOURCE_FAILED );
    }

    fclose( file );
#endif
    *olen = len;

    return( 0 );
}

//NIST 800-90A 8.6.X
//Generate Pseudorandom bits with a Derivation Function
//CTR_DRBG_Generate_algorithm
//--> 1) working_state: *p_rng
//--> 2) requested_number_of_bits: output_len
//--> 3) additional_input: *additional
//Output
//--> 1) status: return status
//--> 2) returned_bits: *output
//--> 3) working_state: *p_rng(aes_ctx, reseed_counter
int stack_info_entropy_poll( void *data, unsigned char *output, size_t len, size_t *olen )
{
    ((void) data);

    *olen = 0;
#ifdef EP_DRBG
	TASK tid;
	extern OsStruct Os;			// Partition control structure
	char tasknamebuf[16];
	ui32 stack_size;
	ui32 temp = 0;
	for (tid = Os.TaskList.head; tid; tid = tid->query_bck)
	{
		//-----------------------------------------------------------------
		// Print initial stack size and amount used.
		//-----------------------------------------------------------------
		memcpy(tasknamebuf, tid->name.str, 8);
		tasknamebuf[8] = NULL;	// added NULL string
		stack_size = OsBufSize((StackSize)tid->stack_size);
		temp = ((ui32)tid->stack_low + (ui32)tid->timer.time_due + (ui16)rand());
		output = ((ui32)output << 32) | ((ui32)temp);
		len += sizeof(temp);
	}
#endif
    *olen = len;

    return( 0 );
}

int entropy_add_source( entropy_context *ctx, f_source_ptr f_source, void *p_source, size_t threshold )
{
    int index, ret = 0;

    index = ctx->source_count;
    if( index >= ENTROPY_MAX_SOURCES )
    {
        ret = ERR_ENTROPY_MAX_SOURCES;
        goto exit;
    }

    ctx->source[index].f_source = f_source;
    ctx->source[index].p_source = p_source;
    ctx->source[index].threshold = threshold;

    ctx->source_count++;

exit:
    return( ret );
}

// Entropy accumulator update
static int entropy_update( entropy_context *ctx, unsigned char source_id, const unsigned char *data, size_t len )
{
    unsigned char header[2];
    unsigned char tmp[ENTROPY_BLOCK_SIZE];
    size_t use_len = len;
    const unsigned char *p = data;

    if( use_len > ENTROPY_BLOCK_SIZE )
    {
#if defined(CTR_DRBG_SHA512)
        sha512( data, len, tmp, 0 );
#else
        sha256( data, len, tmp, 0 );
#endif
        p = tmp;
        use_len = ENTROPY_BLOCK_SIZE;
    }

    header[0] = source_id;
    header[1] = use_len & 0xFF;

#if defined(CTR_DRBG_SHA512)
    sha512_update( &ctx->accumulator, header, 2 );
    sha512_update( &ctx->accumulator, p, use_len );
#else
    sha256_update( &ctx->accumulator, header, 2 );
    sha256_update( &ctx->accumulator, p, use_len );
#endif

    return( 0 );
}

// Run through the different sources to add entropy to our accumulator
static int entropy_gather_internal( entropy_context *ctx )
{
    int ret, i;
    unsigned char buf[ENTROPY_MAX_GATHER];
    size_t olen;

    if( ctx->source_count == 0 )
        return( ERR_ENTROPY_NO_SOURCES_DEFINED );

    // Run through our entropy sources
    for( i = 0; i < ctx->source_count; i++ )
    {
        olen = 0;
        if( ( ret = ctx->source[i].f_source( ctx->source[i].p_source,
                        buf, ENTROPY_MAX_GATHER, &olen ) ) != 0 )
        {
            return( ret );
        }

        // Add if we actually gathered something
        if( olen > 0 )
        {
            entropy_update( ctx, (unsigned char) i, buf, olen );
            ctx->source[i].size += olen;
        }
    }

    return( 0 );
}

int entropy_func( void *data, unsigned char *output, size_t len )
{
    int ret, count = 0, i, reached;
    entropy_context *ctx = (entropy_context *) data;
    unsigned char buf[ENTROPY_BLOCK_SIZE];

    if( len > ENTROPY_BLOCK_SIZE )
        return( ERR_ENTROPY_SOURCE_FAILED );

    // Always gather extra entropy before a call
    do
    {
        if( count++ > ENTROPY_MAX_LOOP )
        {
            ret = ERR_ENTROPY_SOURCE_FAILED;
            goto exit;
        }

        if( ( ret = entropy_gather_internal( ctx ) ) != 0 )
            goto exit;

        reached = 0;

        for( i = 0; i < ctx->source_count; i++ )
            if( ctx->source[i].size >= ctx->source[i].threshold )
                reached++;
    }
    while( reached != ctx->source_count );

    memset( buf, 0, ENTROPY_BLOCK_SIZE );

#if defined(CTR_DRBG_SHA512)
    sha512_finish( &ctx->accumulator, buf );

    /*
     * Reset accumulator and counters and recycle existing entropy
     */
    memset( &ctx->accumulator, 0, sizeof( sha512_context ) );
    sha512_starts( &ctx->accumulator, 0 );
    sha512_update( &ctx->accumulator, buf, ENTROPY_BLOCK_SIZE );

    /*
     * Perform second SHA-512 on entropy
     */
    sha512( buf, ENTROPY_BLOCK_SIZE, buf, 0 );
#else
    sha256_finish( &ctx->accumulator, buf );

    /*
     * Reset accumulator and counters and recycle existing entropy
     */
    memset( &ctx->accumulator, 0, sizeof( sha256_context ) );
    sha256_starts( &ctx->accumulator, 0 );
    sha256_update( &ctx->accumulator, buf, ENTROPY_BLOCK_SIZE );

    /*
     * Perform second SHA-256 on entropy
     */
    sha256( buf, ENTROPY_BLOCK_SIZE, buf, 0 );
#endif

    for( i = 0; i < ctx->source_count; i++ )
        ctx->source[i].size = 0;

    memcpy( output, buf, len );

    ret = 0;

exit:
    return( ret );
}

void entropy_free( entropy_context *ctx )
{
    mercury_zeroize( ctx, sizeof( entropy_context ) );
}

//brief          SHA-256 context setup
//param ctx      context to be initialized
//param is224    0 = use SHA256, 1 = use SHA224
static inline void sha2_starts( sha256_context *ctx, int is224 ) {
    sha256_starts( ctx, is224 );
}

void sha256_init1( sha256_context *ctx )
{
    memset( ctx, 0, sizeof( sha256_context ) );
}

void sha256_free( sha256_context *ctx )
{
    if( ctx == NULL )
        return;

    mercury_zeroize( ctx, sizeof( sha256_context ) );
}

void sha256_process1( sha256_context *ctx, const unsigned char data[64] )
{
    uint32_t temp1, temp2, W[64];
    uint32_t A, B, C, D, E, F, G, H;

    GET_UINT32_BE( W[ 0], data,  0 );
    GET_UINT32_BE( W[ 1], data,  4 );
    GET_UINT32_BE( W[ 2], data,  8 );
    GET_UINT32_BE( W[ 3], data, 12 );
    GET_UINT32_BE( W[ 4], data, 16 );
    GET_UINT32_BE( W[ 5], data, 20 );
    GET_UINT32_BE( W[ 6], data, 24 );
    GET_UINT32_BE( W[ 7], data, 28 );
    GET_UINT32_BE( W[ 8], data, 32 );
    GET_UINT32_BE( W[ 9], data, 36 );
    GET_UINT32_BE( W[10], data, 40 );
    GET_UINT32_BE( W[11], data, 44 );
    GET_UINT32_BE( W[12], data, 48 );
    GET_UINT32_BE( W[13], data, 52 );
    GET_UINT32_BE( W[14], data, 56 );
    GET_UINT32_BE( W[15], data, 60 );

#define  SHR(x,n) ((x & 0xFFFFFFFF) >> n)
#define ROTR(x,n) (SHR(x,n) | (x << (32 - n)))

#define S0(x) (ROTR(x, 7) ^ ROTR(x,18) ^  SHR(x, 3))
#define S1(x) (ROTR(x,17) ^ ROTR(x,19) ^  SHR(x,10))

#define S2(x) (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define S3(x) (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))

#define F0(x,y,z) ((x & y) | (z & (x | y)))
#define F1(x,y,z) (z ^ (x & (y ^ z)))

#define R(t)                                    \
(                                               \
    W[t] = S1(W[t -  2]) + W[t -  7] +          \
           S0(W[t - 15]) + W[t - 16]            \
)

#define P(a,b,c,d,e,f,g,h,x,K)                  \
{                                               \
    temp1 = h + S3(e) + F1(e,f,g) + K + x;      \
    temp2 = S2(a) + F0(a,b,c);                  \
    d += temp1; h = temp1 + temp2;              \
}

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

    P( A, B, C, D, E, F, G, H, W[ 0], 0x428A2F98 );
    P( H, A, B, C, D, E, F, G, W[ 1], 0x71374491 );
    P( G, H, A, B, C, D, E, F, W[ 2], 0xB5C0FBCF );
    P( F, G, H, A, B, C, D, E, W[ 3], 0xE9B5DBA5 );
    P( E, F, G, H, A, B, C, D, W[ 4], 0x3956C25B );
    P( D, E, F, G, H, A, B, C, W[ 5], 0x59F111F1 );
    P( C, D, E, F, G, H, A, B, W[ 6], 0x923F82A4 );
    P( B, C, D, E, F, G, H, A, W[ 7], 0xAB1C5ED5 );
    P( A, B, C, D, E, F, G, H, W[ 8], 0xD807AA98 );
    P( H, A, B, C, D, E, F, G, W[ 9], 0x12835B01 );
    P( G, H, A, B, C, D, E, F, W[10], 0x243185BE );
    P( F, G, H, A, B, C, D, E, W[11], 0x550C7DC3 );
    P( E, F, G, H, A, B, C, D, W[12], 0x72BE5D74 );
    P( D, E, F, G, H, A, B, C, W[13], 0x80DEB1FE );
    P( C, D, E, F, G, H, A, B, W[14], 0x9BDC06A7 );
    P( B, C, D, E, F, G, H, A, W[15], 0xC19BF174 );
    P( A, B, C, D, E, F, G, H, R(16), 0xE49B69C1 );
    P( H, A, B, C, D, E, F, G, R(17), 0xEFBE4786 );
    P( G, H, A, B, C, D, E, F, R(18), 0x0FC19DC6 );
    P( F, G, H, A, B, C, D, E, R(19), 0x240CA1CC );
    P( E, F, G, H, A, B, C, D, R(20), 0x2DE92C6F );
    P( D, E, F, G, H, A, B, C, R(21), 0x4A7484AA );
    P( C, D, E, F, G, H, A, B, R(22), 0x5CB0A9DC );
    P( B, C, D, E, F, G, H, A, R(23), 0x76F988DA );
    P( A, B, C, D, E, F, G, H, R(24), 0x983E5152 );
    P( H, A, B, C, D, E, F, G, R(25), 0xA831C66D );
    P( G, H, A, B, C, D, E, F, R(26), 0xB00327C8 );
    P( F, G, H, A, B, C, D, E, R(27), 0xBF597FC7 );
    P( E, F, G, H, A, B, C, D, R(28), 0xC6E00BF3 );
    P( D, E, F, G, H, A, B, C, R(29), 0xD5A79147 );
    P( C, D, E, F, G, H, A, B, R(30), 0x06CA6351 );
    P( B, C, D, E, F, G, H, A, R(31), 0x14292967 );
    P( A, B, C, D, E, F, G, H, R(32), 0x27B70A85 );
    P( H, A, B, C, D, E, F, G, R(33), 0x2E1B2138 );
    P( G, H, A, B, C, D, E, F, R(34), 0x4D2C6DFC );
    P( F, G, H, A, B, C, D, E, R(35), 0x53380D13 );
    P( E, F, G, H, A, B, C, D, R(36), 0x650A7354 );
    P( D, E, F, G, H, A, B, C, R(37), 0x766A0ABB );
    P( C, D, E, F, G, H, A, B, R(38), 0x81C2C92E );
    P( B, C, D, E, F, G, H, A, R(39), 0x92722C85 );
    P( A, B, C, D, E, F, G, H, R(40), 0xA2BFE8A1 );
    P( H, A, B, C, D, E, F, G, R(41), 0xA81A664B );
    P( G, H, A, B, C, D, E, F, R(42), 0xC24B8B70 );
    P( F, G, H, A, B, C, D, E, R(43), 0xC76C51A3 );
    P( E, F, G, H, A, B, C, D, R(44), 0xD192E819 );
    P( D, E, F, G, H, A, B, C, R(45), 0xD6990624 );
    P( C, D, E, F, G, H, A, B, R(46), 0xF40E3585 );
    P( B, C, D, E, F, G, H, A, R(47), 0x106AA070 );
    P( A, B, C, D, E, F, G, H, R(48), 0x19A4C116 );
    P( H, A, B, C, D, E, F, G, R(49), 0x1E376C08 );
    P( G, H, A, B, C, D, E, F, R(50), 0x2748774C );
    P( F, G, H, A, B, C, D, E, R(51), 0x34B0BCB5 );
    P( E, F, G, H, A, B, C, D, R(52), 0x391C0CB3 );
    P( D, E, F, G, H, A, B, C, R(53), 0x4ED8AA4A );
    P( C, D, E, F, G, H, A, B, R(54), 0x5B9CCA4F );
    P( B, C, D, E, F, G, H, A, R(55), 0x682E6FF3 );
    P( A, B, C, D, E, F, G, H, R(56), 0x748F82EE );
    P( H, A, B, C, D, E, F, G, R(57), 0x78A5636F );
    P( G, H, A, B, C, D, E, F, R(58), 0x84C87814 );
    P( F, G, H, A, B, C, D, E, R(59), 0x8CC70208 );
    P( E, F, G, H, A, B, C, D, R(60), 0x90BEFFFA );
    P( D, E, F, G, H, A, B, C, R(61), 0xA4506CEB );
    P( C, D, E, F, G, H, A, B, R(62), 0xBEF9A3F7 );
    P( B, C, D, E, F, G, H, A, R(63), 0xC67178F2 );

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
    ctx->state[5] += F;
    ctx->state[6] += G;
    ctx->state[7] += H;
}

// SHA-256 process buffer
void sha256_update( sha256_context *ctx, const unsigned char *input, size_t ilen )
{
    size_t fill;
    uint32_t left;

    if( ilen == 0 )
        return;

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += (uint32_t) ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < (uint32_t) ilen )
        ctx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy( (void *) (ctx->buffer + left), input, fill );
        sha256_process1( ctx, ctx->buffer );
        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 64 )
    {
        sha256_process1( ctx, input );
        input += 64;
        ilen  -= 64;
    }

    if( ilen > 0 )
        memcpy( (void *) (ctx->buffer + left), input, ilen );
}

// SHA-256 final digest
void sha256_finish( sha256_context *ctx, unsigned char output[32] )
{
    uint32_t last, padn;
    uint32_t high, low;
    unsigned char msglen[8];

    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_UINT32_BE( high, msglen, 0 );
    PUT_UINT32_BE( low,  msglen, 4 );

    last = ctx->total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    sha256_update( ctx, sha256_padding, padn );
    sha256_update( ctx, msglen, 8 );

    PUT_UINT32_BE( ctx->state[0], output,  0 );
    PUT_UINT32_BE( ctx->state[1], output,  4 );
    PUT_UINT32_BE( ctx->state[2], output,  8 );
    PUT_UINT32_BE( ctx->state[3], output, 12 );
    PUT_UINT32_BE( ctx->state[4], output, 16 );
    PUT_UINT32_BE( ctx->state[5], output, 20 );
    PUT_UINT32_BE( ctx->state[6], output, 24 );

    if( ctx->is224 == 0 )
        PUT_UINT32_BE( ctx->state[7], output, 28 );
}

// output = SHA-256( input buffer )
void sha256( const unsigned char *input, size_t ilen, unsigned char output[32], int is224 )
{
    sha256_context ctx;

    sha256_init1( &ctx );
    sha256_starts( &ctx, is224 );
    sha256_update( &ctx, input, ilen );
    sha256_finish( &ctx, output );
    sha256_free( &ctx );
}

// SHA-256 context setup
void sha256_starts( sha256_context *ctx, int is224 )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    if( is224 == 0 ) // SHA-256
    {
        ctx->state[0] = 0x6A09E667;
        ctx->state[1] = 0xBB67AE85;
        ctx->state[2] = 0x3C6EF372;
        ctx->state[3] = 0xA54FF53A;
        ctx->state[4] = 0x510E527F;
        ctx->state[5] = 0x9B05688C;
        ctx->state[6] = 0x1F83D9AB;
        ctx->state[7] = 0x5BE0CD19;
    }
    else // SHA-224
    {
        ctx->state[0] = 0xC1059ED8;
        ctx->state[1] = 0x367CD507;
        ctx->state[2] = 0x3070DD17;
        ctx->state[3] = 0xF70E5939;
        ctx->state[4] = 0xFFC00B31;
        ctx->state[5] = 0x68581511;
        ctx->state[6] = 0x64F98FA7;
        ctx->state[7] = 0xBEFA4FA4;
    }
    ctx->is224 = is224;
}

#if defined(CTR_DRBG_SHA512)
void sha512_init1( sha512_context *ctx )
{
    memset( ctx, 0, sizeof( sha512_context ) );
}

void sha512_free( sha512_context *ctx )
{
    if( ctx == NULL )
        return;

    mercury_zeroize( ctx, sizeof( sha512_context ) );
}

// SHA-512 context setup
void sha512_starts( sha512_context *ctx, int is384 )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    if( is384 == 0 )
    {
        // SHA-512
        ctx->state[0] = UL64(0x6A09E667F3BCC908);
        ctx->state[1] = UL64(0xBB67AE8584CAA73B);
        ctx->state[2] = UL64(0x3C6EF372FE94F82B);
        ctx->state[3] = UL64(0xA54FF53A5F1D36F1);
        ctx->state[4] = UL64(0x510E527FADE682D1);
        ctx->state[5] = UL64(0x9B05688C2B3E6C1F);
        ctx->state[6] = UL64(0x1F83D9ABFB41BD6B);
        ctx->state[7] = UL64(0x5BE0CD19137E2179);
    }
    else
    {
        // SHA-384
        ctx->state[0] = UL64(0xCBBB9D5DC1059ED8);
        ctx->state[1] = UL64(0x629A292A367CD507);
        ctx->state[2] = UL64(0x9159015A3070DD17);
        ctx->state[3] = UL64(0x152FECD8F70E5939);
        ctx->state[4] = UL64(0x67332667FFC00B31);
        ctx->state[5] = UL64(0x8EB44A8768581511);
        ctx->state[6] = UL64(0xDB0C2E0D64F98FA7);
        ctx->state[7] = UL64(0x47B5481DBEFA4FA4);
    }

    ctx->is384 = is384;
}

void sha512_process1( sha512_context *ctx, const unsigned char data[128] )
{
    int i;
    uint64_t temp1, temp2, W[80];
    uint64_t A, B, C, D, E, F, G, H;

#define  SHR(x,n) (x >> n)
#define ROTR(x,n) (SHR(x,n) | (x << (64 - n)))

#define S0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^  SHR(x, 7))
#define S1(x) (ROTR(x,19) ^ ROTR(x,61) ^  SHR(x, 6))

#define S2(x) (ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39))
#define S3(x) (ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41))

#define F0(x,y,z) ((x & y) | (z & (x | y)))
#define F1(x,y,z) (z ^ (x & (y ^ z)))

#define P(a,b,c,d,e,f,g,h,x,K)                  \
{                                               \
    temp1 = h + S3(e) + F1(e,f,g) + K + x;      \
    temp2 = S2(a) + F0(a,b,c);                  \
    d += temp1; h = temp1 + temp2;              \
}

    for( i = 0; i < 16; i++ )
    {
        GET_UINT64_BE( W[i], data, i << 3 );
    }

    for( ; i < 80; i++ )
    {
        W[i] = S1(W[i -  2]) + W[i -  7] +
               S0(W[i - 15]) + W[i - 16];
    }

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];
    i = 0;

    do
    {
        P( A, B, C, D, E, F, G, H, W[i], K[i] ); i++;
        P( H, A, B, C, D, E, F, G, W[i], K[i] ); i++;
        P( G, H, A, B, C, D, E, F, W[i], K[i] ); i++;
        P( F, G, H, A, B, C, D, E, W[i], K[i] ); i++;
        P( E, F, G, H, A, B, C, D, W[i], K[i] ); i++;
        P( D, E, F, G, H, A, B, C, W[i], K[i] ); i++;
        P( C, D, E, F, G, H, A, B, W[i], K[i] ); i++;
        P( B, C, D, E, F, G, H, A, W[i], K[i] ); i++;
    }
    while( i < 80 );

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
    ctx->state[5] += F;
    ctx->state[6] += G;
    ctx->state[7] += H;
}

// SHA-512 process buffer
void sha512_update( sha512_context *ctx, const unsigned char *input, size_t ilen )
{
    size_t fill;
    unsigned int left;

    if( ilen == 0 )
        return;

    left = (unsigned int) (ctx->total[0] & 0x7F);
    fill = 128 - left;

    ctx->total[0] += (uint64_t) ilen;

    if( ctx->total[0] < (uint64_t) ilen )
        ctx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy( (void *) (ctx->buffer + left), input, fill );
        sha512_process1( ctx, ctx->buffer );
        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 128 )
    {
        sha512_process1( ctx, input );
        input += 128;
        ilen  -= 128;
    }

    if( ilen > 0 )
        memcpy( (void *) (ctx->buffer + left), input, ilen );
}

// SHA-512 final digest
void sha512_finish( sha512_context *ctx, unsigned char output[64] )
{
    size_t last, padn;
    uint64_t high, low;
    unsigned char msglen[16];

    high = ( ctx->total[0] >> 61 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_UINT64_BE( high, msglen, 0 );
    PUT_UINT64_BE( low,  msglen, 8 );

    last = (size_t)( ctx->total[0] & 0x7F );
    padn = ( last < 112 ) ? ( 112 - last ) : ( 240 - last );

    sha512_update( ctx, sha512_padding, padn );
    sha512_update( ctx, msglen, 16 );

    PUT_UINT64_BE( ctx->state[0], output,  0 );
    PUT_UINT64_BE( ctx->state[1], output,  8 );
    PUT_UINT64_BE( ctx->state[2], output, 16 );
    PUT_UINT64_BE( ctx->state[3], output, 24 );
    PUT_UINT64_BE( ctx->state[4], output, 32 );
    PUT_UINT64_BE( ctx->state[5], output, 40 );

    if( ctx->is384 == 0 )
    {
        PUT_UINT64_BE( ctx->state[6], output, 48 );
        PUT_UINT64_BE( ctx->state[7], output, 56 );
    }
}

// output = SHA-512( input buffer )
void sha512( const unsigned char *input, size_t ilen, unsigned char output[64], int is384 )
{
    sha512_context ctx;

    sha512_init1( &ctx );
    sha512_starts( &ctx, is384 );
    sha512_update( &ctx, input, ilen );
    sha512_finish( &ctx, output );
    sha512_free( &ctx );
}

// SHA-512 HMAC context setup
void sha512_hmac_starts( sha512_context *ctx, const unsigned char *key, size_t keylen, int is384 )
{
    size_t i;
    unsigned char sum[64];

    if( keylen > 128 )
    {
        sha512( key, keylen, sum, is384 );
        keylen = ( is384 ) ? 48 : 64;
        key = sum;
    }

    memset( ctx->ipad, 0x36, 128 );
    memset( ctx->opad, 0x5C, 128 );

    for( i = 0; i < keylen; i++ )
    {
        ctx->ipad[i] = (unsigned char)( ctx->ipad[i] ^ key[i] );
        ctx->opad[i] = (unsigned char)( ctx->opad[i] ^ key[i] );
    }

    sha512_starts( ctx, is384 );
    sha512_update( ctx, ctx->ipad, 128 );

    mercury_zeroize( sum, sizeof( sum ) );
}

// SHA-512 HMAC process buffer
void sha512_hmac_update( sha512_context  *ctx, const unsigned char *input, size_t ilen )
{
    sha512_update( ctx, input, ilen );
}

//SHA-512 HMAC final digest
void sha512_hmac_finish( sha512_context *ctx, unsigned char output[64] )
{
    int is384, hlen;
    unsigned char tmpbuf[64];

    is384 = ctx->is384;
    hlen = ( is384 == 0 ) ? 64 : 48;

    sha512_finish( ctx, tmpbuf );
    sha512_starts( ctx, is384 );
    sha512_update( ctx, ctx->opad, 128 );
    sha512_update( ctx, tmpbuf, hlen );
    sha512_finish( ctx, output );

    mercury_zeroize( tmpbuf, sizeof( tmpbuf ) );
}

// SHA-512 HMAC context reset
void sha512_hmac_reset( sha512_context *ctx )
{
    sha512_starts( ctx, ctx->is384 );
    sha512_update( ctx, ctx->ipad, 128 );
}

// Checkup routine
int sha512_self_test( int verbose )
{
    int i, j, k, buflen, ret = 0;
    unsigned char buf[1024];
    unsigned char sha512sum[64];
    sha512_context ctx;

    sha512_init1( &ctx );

    for( i = 0; i < 6; i++ )
    {
        j = i % 3;
        k = i < 3;

        if( verbose != 0 )
        	printf( "  SHA-%d test #%d: ", 512 - k * 128, j + 1 );

        sha512_starts( &ctx, k );

        if( j == 2 )
        {
            memset( buf, 'a', buflen = 1000 );

            for( j = 0; j < 1000; j++ )
                sha512_update( &ctx, buf, buflen );
        }
        else
            sha512_update( &ctx, sha512_test_buf[j],
                                 sha512_test_buflen[j] );

        sha512_finish( &ctx, sha512sum );

        if( memcmp( sha512sum, sha512_test_sum[i], 64 - k * 16 ) != 0 )
        {
            if( verbose != 0 )
            	printf( "failed\n" );

            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
        	printf( "passed\n" );
    }

    if( verbose != 0 )
    	printf( "\n" );

    for( i = 0; i < 14; i++ )
    {
        j = i % 7;
        k = i < 7;

        if( verbose != 0 )
        	printf( "  HMAC-SHA-%d test #%d: ", 512 - k * 128, j + 1 );

        if( j == 5 || j == 6 )
        {
            memset( buf, '\xAA', buflen = 131 );
            sha512_hmac_starts( &ctx, buf, buflen, k );
        }
        else
            sha512_hmac_starts( &ctx, sha512_hmac_test_key[j],
                                      sha512_hmac_test_keylen[j], k );

        sha512_hmac_update( &ctx, sha512_hmac_test_buf[j],
                                  sha512_hmac_test_buflen[j] );

        sha512_hmac_finish( &ctx, sha512sum );

        buflen = ( j == 4 ) ? 16 : 64 - k * 16;

        if( memcmp( sha512sum, sha512_hmac_test_sum[i], buflen ) != 0 )
        {
            if( verbose != 0 )
                printf( "failed\n" );

            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
        	printf( "passed\n" );
    }

    if( verbose != 0 )
    	printf( "\n" );

exit:
    sha512_free( &ctx );

    return( ret );
}
#endif //endif for #if defined(CTR_DRBG_SHA512)

static void UnsignedLongLongToString (unsigned long long num, char *string)
{
    int position;
    unsigned long long absnum;
    char tempString[21];
    int minus=0;
// Put null at end of string
    position = sizeof (tempString) - 1;
    tempString[position] = 0;
    absnum = num;

// Alway convert the lowest digit
    position = position - 1;
    tempString[position] = (absnum % 10) + '0';
    absnum = absnum / 10;

    while (absnum != 0) {
    	position = position - 1;
	tempString[position] = (absnum % 10 + '0');
	absnum = absnum / 10;
    }

    memcpy (string, &tempString[position], sizeof(tempString) - position);
}

//NIST 800-90A B.5.1.1
//m is the number of bits needed to represent 9,223,372,036,854,775,807 (or 7FFF,FFFF,FFFF,FFFF)
//Conver the Random Bits to a Random Number using approved Simple Discard Method
ui64 convertRBtoRN(unsigned char *buf, int buf_size) {
	int i, j, z=0;
	int bit = 0;
	ui64 a = 0; //a
	ui64 c = 0;
	ui64 m = 0xFFFFFFFFFFFFFFFE;
	for(i=0; i<buf_size; i++) { //go through each byte
		for(j=0; j<8; j++) {	//8 bits per unsigned char
			bit = (buf[i] & ( 1 << j )) >> j;
			c += ((pow(2, z)) * bit);
			if((c <= m) && (c >= a)){	//account for rollover
				a += ((pow(2, z)) * bit);
			} else {
				//printf("at the break\n");
				break;
			}
			z++;
		}
	}
	return a;
}

int fRngDRBGGetRnd( unsigned char *pRnd ) {
	int ret;
    unsigned char buf[64];
    unsigned char hash[20];
	int nPersStringLength = 0;
	unsigned char cPersString[128];
	char cMacAddr[12];
	unsigned long long milliseconds;
    const char *pers = "lk'ja^1s345?df6li&UH;AOs{67!LIh3j(u72LKH8#JS";	//random string

	if ( nRngDRBGInitOk == 0 ) {
		//NIST 800-90A 11.3.2
		if((ret = ctr_drbg_self_test(VERBOSE)) != 0) {
			//NIST 800-90A 11.3.6.2
			return ERR_CTR_DRBG_CATASTROPHIC_FAIL;
		}
		
#ifdef EP_DRBG
		milliseconds = SysCounter();

#else
		struct timeval te;
		gettimeofday(&te, NULL); // get current time
		milliseconds = (te.tv_sec*1000LL << 32) + te.tv_usec/1000;

		struct ifreq s;
		int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

		strcpy(s.ifr_name, "eth0");
		if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
			snprintf(cMacAddr, sizeof(cMacAddr), "%02x%02x%02x%02x%02x%02x", (unsigned char) s.ifr_addr.sa_data[0],
					(unsigned char) s.ifr_addr.sa_data[1], (unsigned char) s.ifr_addr.sa_data[2],
					(unsigned char) s.ifr_addr.sa_data[3], (unsigned char) s.ifr_addr.sa_data[4],
					(unsigned char) s.ifr_addr.sa_data[5]);
		}

#endif

		UnsignedLongLongToString(milliseconds, cPersString);
		nPersStringLength = strlen(cPersString);
#ifndef EP_DRBG
		memcpy(&cPersString[nPersStringLength], cMacAddr, strlen(cMacAddr));
		nPersStringLength += strlen(cMacAddr);
#endif
		memcpy(&cPersString[nPersStringLength], pers, strlen(pers));
		nPersStringLength += strlen(pers);
		
		entropy_init( &entropy );
		if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy, (const unsigned char *) cPersString, nPersStringLength ) ) != 0 )
		{
			return ret;
		}
	}

	ctr_drbg_set_prediction_resistance( &ctr_drbg, CTR_DRBG_PR_OFF );

	if(ctr_drbg.reseed_counter == SELF_TEST_COUNTER) {
		if((ret = ctr_drbg_self_test(DRBG_VERBOSE)) != 0) {
			//NIST 800-90A 11.3.6.2
			return ERR_CTR_DRBG_CATASTROPHIC_FAIL;
		}
	}
	ret = ctr_drbg_random( &ctr_drbg, buf, sizeof( buf ) );

	if( ret != 0 )
	{
		return 0;
	}

	memcpy(pRnd, buf, 16);

	return 1;
}