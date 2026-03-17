#ifndef _FRAMES_H
#define _FRAMES_H

// https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#exchanging_data_frames

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WSOP_CONTINUE 0x0
#define WSOP_TEXT     0x1
#define WSOP_BINARY   0x2
#define WSOP_EXIT     0x8
#define WSOP_PING     0x9
#define WSOP_PONG     0xA

// RSV1, RSV2, RSV3: will be ignored.
struct ws_in_frame {
    bool fin;
    bool mask;
    uint8_t opcode;
    unsigned char* payload;
    uint64_t payload_len;
};

struct ws_out_frame {
    unsigned char* payload;
    size_t payload_len;
};

/*
 * Parses raw data buffer and writes it to dest, 
 * returns 1 on error  
 */
int ws_parse_frame(unsigned char* buf, size_t buf_size, struct ws_in_frame* dest);

/*
 * Takes in raw data buffer and writes it to dest.
 * Out frame has 0x1 opcode and fin set to 1
 */
int ws_to_frame(unsigned char* buf, size_t buf_size, 
                struct ws_out_frame* dest, int opcode);

#endif