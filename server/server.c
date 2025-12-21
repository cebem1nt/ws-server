#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "include/frames.h"
#include "include/structs.h"
#include "include/structs.h"
#include "include/crypt.h"

#define HTTPP_IMPLEMENTATION
#include "include/httpp.h"

#define PORT 8080
#define LISTEN_BACKLOG 10
#define MAX_MSG_SIZE 2048

typedef struct {
    int client_sfd;
    clients_hset chs;
    rooms_hmap rhm;
} thread_arg_t;

static pthread_mutex_t maps_mutex = PTHREAD_MUTEX_INITIALIZER;

/* 
 * manpages: socket(2), sockaddr_in, listen(2),
 *           ip(7), bind(2), accept(2), htonl
 *
 */

void 
err_exit(const char* reason) 
{
    perror(reason);
    exit(EXIT_FAILURE);
}

char*
get_room_id(char* msg) 
{
    char* p = strchr(msg, ':');
    
    if (p && *(p+1) != '\0') {
        return strdup(p+1);
    }

    return NULL;
}

int
handle_websocket(int client_sfd, char** client_room, char* msg_raw, 
                 size_t msg_size, rooms_hmap rhm)
{
    unsigned char* umsg_raw = (unsigned char*) msg_raw;
    struct ws_in_frame  inf;
    struct ws_out_frame outf;

    if (ws_parse_frame(umsg_raw, msg_size, &inf)) {
        printf("Error when parsing ws frame.\n");
        return 1;
    }

    char* message = (char*) inf.payload;

    switch (inf.opcode) {
    case WSOP_TEXT:
        break; // This is text, we can proceed it

    case WSOP_EXIT:
    default:
        return 1;
    }

    if (message[0] != '{') {
        *client_room = get_room_id(message);
        rooms_hmap_append_client(rhm, *client_room, client_sfd);
    }
    
    else if (*client_room) { // It is json message, broadcast it to anyone in the same room
        int* clients_in_room = rooms_hmap_get(rhm, *client_room);

        for (int i = 0; i < MAX_CLIENTS_PER_ROOM; i++) {
            int client = clients_in_room[i];

            if (client != -1 && client != client_sfd) {
                ws_to_frame(inf.payload, inf.payload_len, &outf);
                write(client, outf.payload, outf.payload_len);
            }
        } 

        free(clients_in_room);
    }

    free(inf.payload);
    return 0;
}

/*
 * Gets raw http request, returns SWITCHING_PROTOCOL  
 * respones if request is fine, otherwise null
 */
char*
handshake(char* request_raw, size_t n, size_t* response_len)
{
    HTTPP_NEW_REQ(req, 100);
    httpp_parse_request(request_raw, n, &req);

    httpp_header_t* key_header = httpp_find_header(req, "Sec-WebSocket-Key");

    if (req.method != HTTPP_METHOD_GET || key_header == NULL)
        return NULL; // Invalid request. We aint handle normal http. 

    char* key = httpp_span_to_str(&key_header->value);
    char* signed_key = sign_key(key);

    HTTPP_NEW_RES(res, 5, 101); // Switching protocols

    httpp_res_add_header(&res, "Upgrade", "websocket");
    httpp_res_add_header(&res, "Connection", "Upgrade");
    httpp_res_add_header(&res, "Sec-WebSocket-Accept", signed_key);

    char* out = httpp_res_to_raw(&res, response_len);

    free(key);
    free(signed_key);
    httpp_res_free_added(&res);
    return out;
}

void* 
hadle_client(void* arg_v) 
{
    thread_arg_t* arg = (thread_arg_t*) arg_v;
    int client_sfd = arg->client_sfd;
    clients_hset chs = arg->chs;
    rooms_hmap rhm = arg->rhm;
    
    char   buf[MAX_MSG_SIZE];
    char*  client_room = NULL;
    size_t n;

    while ((n = read(client_sfd, buf, MAX_MSG_SIZE)) > 0 ) {
        printf("Message from (%i), size: %zd\n", client_sfd, n);

        if (client_room) {
            printf("\t(%i) room: %s\n", client_sfd, client_room);
        } else {
            printf("\t(%i) has no room.\n", client_sfd);
        }

        pthread_mutex_lock(&maps_mutex);
        bool is_recognized = clients_hset_has(chs, client_sfd);
        pthread_mutex_unlock(&maps_mutex);
        
        /* 
         * If we dont have mapped socket fd, then assume incoming request
         * is webrtc handshake. If its not, but we already handshaked, 
         * treat the buffer as data frame.
         */
        if (!is_recognized) {
            printf("\t(%i) is not recognized, handshake\n", client_sfd);

            size_t response_len;
            char*  response = handshake(buf, n, &response_len);

            if (!response)
                break;
            
            write(client_sfd, response, response_len);

            pthread_mutex_lock(&maps_mutex);
            clients_hset_set(chs, client_sfd);
            pthread_mutex_unlock(&maps_mutex);

            free(response);
        }

        else if (is_recognized) {
            pthread_mutex_lock(&maps_mutex);
            if (handle_websocket(client_sfd, &client_room, buf, n, rhm)) {
                pthread_mutex_unlock(&maps_mutex);
                break;
            }
            pthread_mutex_unlock(&maps_mutex);
        }
    }

    printf("\nBye client! (%i)\n", client_sfd);

    pthread_mutex_lock(&maps_mutex);
    clients_hset_delete(chs, client_sfd);
    rooms_map_delete_client(rhm, client_room, client_sfd);
    pthread_mutex_unlock(&maps_mutex);
    
    close(client_sfd);
    free(client_room);
    free(arg);
    
    return NULL;
}

int 
main()
{
    int server_sfd, client_sfd;

    clients_hset chs = clients_hset_new();
    rooms_hmap rmap = rooms_hmap_new();

    struct sockaddr_in server_addr = {0};
    struct sockaddr    client_addr = {0};

    server_sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sfd == -1)
        err_exit("socket");

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT); 

    int opt = 1;
    setsockopt(server_sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(server_sfd, (struct sockaddr*) &server_addr, sizeof(server_addr)) == -1)
        err_exit("bind");

    if (listen(server_sfd, LISTEN_BACKLOG) == -1)
        err_exit("listen");

    // Listen for any connections
    printf("Server is listening\n");

    while (1) { 
        socklen_t client_addr_s = sizeof(client_addr);

        client_sfd = accept(server_sfd, &client_addr, &client_addr_s);
        if (client_sfd == -1)
            err_exit("accept");
        
        printf("Client (%i) accepted\n\n", client_sfd);

        pthread_t tid;
        thread_arg_t* targ = (thread_arg_t*) malloc(sizeof(thread_arg_t));
        if (!targ)
            err_exit("malloc");

        targ->client_sfd = client_sfd;
        targ->chs = chs;
        targ->rhm = rmap;

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        if (pthread_create(&tid, &attr, hadle_client, targ) != 0)
            err_exit("pthread_create");

        pthread_attr_destroy(&attr);
    }

    return 0;
}