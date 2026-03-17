#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "include/frames.h"

/*
 Server to client frame diagram

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (64)              |
|N|V|V|V|       |S|   (== 127)  |                               |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|               Extended payload length continued               |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                               |          Masking-key          |
+-------------------------------+-------------------------------+
|    Masking-key (continued)    |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - - +
:                     Payload Data continued ...                :
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                     Payload Data continued ...                |
+---------------------------------------------------------------+
*/
int ws_to_frame(unsigned char* buf, size_t buf_size, 
                struct ws_out_frame* out, int opcode) 
{
    const uint8_t fin_opcode = 0x80 | opcode;
    uint64_t payload_len = buf_size;

    size_t header_len = 2; // base header

    if (payload_len <= 125) {
        header_len = 2;
    } 
    else if (payload_len <= 0xFFFF) {
        header_len = 4;
    }
    else {
        header_len = 10;
    }

    // Server must NOT mask frames!
    size_t total_len = header_len + payload_len;
    unsigned char* frame = (unsigned char*) malloc(total_len);

    if (!frame) 
        return 1;

    frame[0] = fin_opcode;

    if (payload_len <= 125) {
        frame[1] = (uint8_t)payload_len;
    } 
    else if (payload_len <= 0xFFFF) {
        frame[1] = 126;
        frame[2] = (uint8_t)((payload_len >> 8) & 0xFF);
        frame[3] = (uint8_t)(payload_len & 0xFF);
    } 
    else {
        frame[1] = 127;
        // write 64-bit big-endian length
        for (int i = 0; i < 8; ++i) {
            frame[2 + i] = (uint8_t)((payload_len >> (56 - 8*i)) & 0xFF);
        }
    }

    memcpy(frame + header_len, buf, payload_len);
    
    out->payload = frame;
    out->payload_len = total_len;

    return 0;
}

/*
 Client to server frame diagram

 0                 1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |          Masking-key          |
|I|S|S|S|  (4)  |A|     (7)     |             (32)              |
|N|V|V|V|       |S|             |                               |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+-------------------------------+
|    Masking-key (continued)    |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - - +
:                     Payload Data continued ...                :
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                     Payload Data continued ...                |
+---------------------------------------------------------------+
*/

int ws_parse_frame(unsigned char* buf, size_t buf_size, struct ws_in_frame* out) 
{
    uint8_t b0 = buf[0];
    uint8_t b1 = buf[1];

    out->fin    = (b0 >> 7) & 0x1;
    out->mask   = (b1 >> 7) & 0x1;
    out->opcode = b0 & 0x0F;

    if (!out->mask)
        return 1;

    uint64_t payload_len = b1 & 0x7F;
    size_t   header_len = 2;

    // Extract payload length
    if (payload_len <= 125) {
        out->payload_len = payload_len;
    } 
    else if (payload_len == 126) {
        if (buf_size < header_len + 2)
            return 1;

        out->payload_len = (uint64_t)((buf[2] << 8) | buf[3]);
        header_len += 2;
    } 
    else if (payload_len == 127) {
        if (buf_size < header_len + 8)
            return 1;
        
        out->payload_len = 0;
        for (int i = 0; i < 8; ++i) {
            out->payload_len = (out->payload_len << 8) | buf[2 + i];
        }
        header_len += 8;
    }

    uint8_t masking_key[4] = {0,0,0,0};

    if (buf_size < header_len + 4) 
        return 1;

    masking_key[0] = buf[header_len + 0];
    masking_key[1] = buf[header_len + 1];
    masking_key[2] = buf[header_len + 2];
    masking_key[3] = buf[header_len + 3];

    header_len += 4;

    out->payload = (unsigned char*) malloc((size_t)out->payload_len + 1);
    if (!out->payload)
        return 1;

    const unsigned char* masked_data = buf + header_len;

    for (uint64_t i = 0; i < out->payload_len; ++i) {
        out->payload[i] = masked_data[i] ^ masking_key[i % 4];
    }

    out->payload[out->payload_len] = '\0';
    return 0;
}