/* 
 * The handshake is the "Web" in WebSockets.
 * Basically what we need is to get the magic string from Sec-WebSocket-Accept
 * and take the sha1 hash of it and send base64 encoding of it
 * 
 * Unfortunately not c lib nor c++ has base64 / sha1 in it
 * Also im not a cryptography specialist so both base64 and sha1 are copypasted
 *
 * Base64: https://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.c
 * SHA1:   https://github.com/zaphoyd/websocketpp/blob/master/websocketpp/sha1/sha1.hpp
 */

#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>

#include "include/crypt.h"

/*
 * The key you have to concatenate with provided client one
 * to accpet the web-scoket comunication.
 * https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#server_handshake_response 
 */
#define GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

static const unsigned char base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

unsigned char* base64_encode(const unsigned char *src, size_t len)
{
	unsigned char *out, *pos;
	const unsigned char *end, *in;
	size_t olen;
	int line_len;

	olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
	olen += olen / 72; /* line feeds */
	olen++; /* nul termination */
	if (olen < len)
		return NULL; /* integer overflow */
	out = (unsigned char*) malloc(olen);
	if (out == NULL)
		return NULL;

	end = src + len;
	in = src;
	pos = out;
	line_len = 0;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
		line_len += 4;
		if (line_len >= 72) {
			*pos++ = '\n';
			line_len = 0;
		}
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
					      (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
		line_len += 4;
	}

	*pos = '\0';
	return out;
}

/*
*****
sha1.hpp is a repackaging of the sha1.cpp and sha1.h files from the smallsha1
library (http://code.google.com/p/smallsha1/) into a single header suitable for
use as a header only library. This conversion was done by Peter Thorson
(webmaster@zaphoyd.com) in 2013. All modifications to the code are redistributed
under the same license as the original, which is listed below.
*****

 Copyright (c) 2011, Micael Hildenborg
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of Micael Hildenborg nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY Micael Hildenborg ''AS IS'' AND ANY
 EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL Micael Hildenborg BE LIABLE FOR ANY
 DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// Rotate an integer value to left.
static unsigned int rol(unsigned int value, unsigned int steps) {
    return ((value << steps) | (value >> (32 - steps)));
}

// Sets the first 16 integers in the buffert to zero.
// Used for clearing the W buffert.
static void clearWBuffert(unsigned int * buffert)
{
    for (int pos = 16; --pos >= 0;)
    {
        buffert[pos] = 0;
    }
}

static void innerHash(unsigned int * result, unsigned int * w)
{
    unsigned int a = result[0];
    unsigned int b = result[1];
    unsigned int c = result[2];
    unsigned int d = result[3];
    unsigned int e = result[4];

    int round = 0;

    #define sha1macro(func,val) \
    { \
        const unsigned int t = rol(a, 5) + (func) + e + val + w[round]; \
        e = d; \
        d = c; \
        c = rol(b, 30); \
        b = a; \
        a = t; \
    }

    while (round < 16)
    {
        sha1macro((b & c) | (~b & d), 0x5a827999)
        ++round;
    }
    while (round < 20)
    {
        w[round] = rol((w[round - 3] ^ w[round - 8] ^ w[round - 14] ^ w[round - 16]), 1);
        sha1macro((b & c) | (~b & d), 0x5a827999)
        ++round;
    }
    while (round < 40)
    {
        w[round] = rol((w[round - 3] ^ w[round - 8] ^ w[round - 14] ^ w[round - 16]), 1);
        sha1macro(b ^ c ^ d, 0x6ed9eba1)
        ++round;
    }
    while (round < 60)
    {
        w[round] = rol((w[round - 3] ^ w[round - 8] ^ w[round - 14] ^ w[round - 16]), 1);
        sha1macro((b & c) | (b & d) | (c & d), 0x8f1bbcdc)
        ++round;
    }
    while (round < 80)
    {
        w[round] = rol((w[round - 3] ^ w[round - 8] ^ w[round - 14] ^ w[round - 16]), 1);
        sha1macro(b ^ c ^ d, 0xca62c1d6)
        ++round;
    }

    #undef sha1macro

    result[0] += a;
    result[1] += b;
    result[2] += c;
    result[3] += d;
    result[4] += e;
}

void SHA1(void* src, size_t bytelength, unsigned char * hash) 
{
    // Init the result array.
    unsigned int result[5] = { 0x67452301, 0xefcdab89, 0x98badcfe,
                               0x10325476, 0xc3d2e1f0 };

    // Cast the void src pointer to be the byte array we can work with.
    unsigned char const * sarray = (unsigned char const *) src;

    // The reusable round buffer
    unsigned int w[80];

    // Loop through all complete 64byte blocks.
    size_t endCurrentBlock;
    size_t currentBlock = 0;

    if (bytelength >= 64) {
        size_t const endOfFullBlocks = bytelength - 64;

        while (currentBlock <= endOfFullBlocks) {
            endCurrentBlock = currentBlock + 64;

            // Init the round buffer with the 64 byte block data.
            for (int roundPos = 0; currentBlock < endCurrentBlock; currentBlock += 4)
            {
                // This line will swap endian on big endian and keep endian on
                // little endian.
                w[roundPos++] = (unsigned int) sarray[currentBlock + 3]
                        | (((unsigned int) sarray[currentBlock + 2]) << 8)
                        | (((unsigned int) sarray[currentBlock + 1]) << 16)
                        | (((unsigned int) sarray[currentBlock]) << 24);
            }
            innerHash(result, w);
        }
    }

    // Handle the last and not full 64 byte block if existing.
    endCurrentBlock = bytelength - currentBlock;
    clearWBuffert(w);
    size_t lastBlockBytes = 0;
    for (;lastBlockBytes < endCurrentBlock; ++lastBlockBytes) {
        w[lastBlockBytes >> 2] |= (unsigned int) sarray[lastBlockBytes + currentBlock] << ((3 - (lastBlockBytes & 3)) << 3);
    }

    w[lastBlockBytes >> 2] |= 0x80 << ((3 - (lastBlockBytes & 3)) << 3);
    if (endCurrentBlock >= 56) {
        innerHash(result, w);
        clearWBuffert(w);
    }
    w[15] = bytelength << 3;
    innerHash(result, w);

    // Store hash in result pointer, and make sure we get in in the correct
    // order on both endian models.
    for (int hashByte = 20; --hashByte >= 0;) {
        hash[hashByte] = (result[hashByte >> 2] >> (((3 - hashByte) & 0x3) << 3)) & 0xff;
    }
}

static char* concat(const char* s1, const char* s2) 
{
	char* out = (char*) malloc(strlen(s1) + strlen(s2) + 1);
	if (!out)
		return NULL;

	strcpy(out, s1);
	strcat(out, s2);

	return out;
}

char* sign_key(const char* key)
{
	char* combined_key = concat(key, GUID);
	unsigned char hash[SHA1_BLOCK_SIZE];
	unsigned char* signature;

	SHA1(combined_key, strlen(combined_key), hash);
	signature = base64_encode(hash, SHA1_BLOCK_SIZE);

	free(combined_key);
	return (char*) signature;
}