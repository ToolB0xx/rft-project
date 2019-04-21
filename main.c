#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>


#define PACKET_SIZE 512
#define TIMEOUT 2
#define MAX_TRIES 8
#define OFFSET_DONE 0xFFFFFFFF

#define RFT_REQUEST 0x1
#define RFT_SIZE 0x2
#define RFT_SEND 0x3
#define RFT_FILE 0x4
#define RFT_RESEND 0x5
#define RFT_ERROR 0x194
#define RFT_ERROR_ACK (0x194 | 0x80000000)

#define FILE_DATA_SIZE (PACKET_SIZE - sizeof(int) - sizeof(int))

struct rft_packet_request {
    unsigned int header;
    char remote_path[PACKET_SIZE - sizeof(int)];
};
struct rft_packet_size {
    unsigned int header;
    unsigned int file_size;
    unsigned char undefined[PACKET_SIZE - sizeof(int)- sizeof(int)];
};
struct rft_packet_send {
    unsigned int header;
    unsigned int file_size;
    unsigned char undefined[PACKET_SIZE - sizeof(int) - sizeof(int)];
};
struct rft_packet_file {
    unsigned int header;
    unsigned int offset;
    unsigned char data[FILE_DATA_SIZE];
};
struct rft_packet_resend {
    unsigned int header;
    unsigned int offset;
    unsigned char undefined[PACKET_SIZE - sizeof(int) - sizeof(int)];
};
struct rft_packet_error {
    unsigned int header;
    char message[PACKET_SIZE - sizeof(int)];
};

// COMMON FUNCTIONS
int send_packet(int socket, struct sockaddr_storage* to_addr, socklen_t to_addr_len, void* packet) {
    if (sendto(socket, packet, PACKET_SIZE, 0, (struct sockaddr*)to_addr, to_addr_len) == -1) {
        perror("send_packet");
    }
    return 0;
}

void handle_error(int socket, struct sockaddr_storage* to_addr, socklen_t to_addrlen, struct rft_packet_error* packet) {
    int tries = MAX_TRIES;
    packet->header |= 0x80000000; // make it into RFT_ERROR_ACK
    while(tries--) {
        // Server isn't going to ack, and not critical for this to arrive, so just send it multiple times
        send_packet(socket, to_addr, to_addrlen, (void*) packet);
    }
    fprintf(stderr, "An error occurred.  The message from the server follows: \n%s\n", packet->message);
    exit(0);
}

unsigned char* wait_for_packet(int socket, unsigned int header, struct sockaddr_storage* from_addr, socklen_t* from_addrlen) {
    unsigned char* packet = malloc(PACKET_SIZE);
    memset(packet, 0, PACKET_SIZE);

    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    if (recvfrom(socket, packet, PACKET_SIZE, 0, (struct sockaddr*)&addr, &addrlen) == -1) {
        if (errno == EAGAIN) {
            // timeout
            return NULL;
        }
        perror("wait_for_packet");
    }
    if (*((unsigned int*)packet) != header) {
        if (*((unsigned int*)packet) == RFT_ERROR) {
            handle_error(socket, &addr, addrlen, (struct rft_packet_error*) packet);
        }
        return NULL;
    }
    if (from_addr != NULL && from_addrlen != NULL) {
        *from_addr = addr;
        *from_addrlen = addrlen;
    }
    return packet;
}

// SERVER-ONLY FUNCTIONS
int bind_socket(char* server_port, struct addrinfo** server_addrinfo) {
    int sockfd = NULL;
    struct addrinfo hints, *addrinfo, *p;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(NULL, server_port, &hints, &addrinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 0;
    }

    for(p = addrinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1) {
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            continue;
        }

        struct timeval timeval;
        timeval.tv_sec = TIMEOUT;
        timeval.tv_usec = 0;

        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeval, sizeof(timeval)) < 0) {
            perror("Couldn't set socket timeout");
        }

        break;
    }

    if (p == NULL || sockfd == NULL) {
        return 0;
    }

    *server_addrinfo = addrinfo;
    return sockfd;
}

void send_file_packet(int socket, struct sockaddr_storage* client_addr, socklen_t client_addr_len, unsigned int offset, unsigned int file_size, unsigned char* buffer) {
    struct rft_packet_file packet;
    packet.header = RFT_FILE;
    packet.offset = offset;

    unsigned int cpylen = FILE_DATA_SIZE;
    if (offset + FILE_DATA_SIZE > file_size) {
        cpylen = file_size - offset;
    }

    memcpy(packet.data, buffer + offset, cpylen);

    send_packet(socket, client_addr, client_addr_len, (void*)&packet);
}

void send_file(int socket, struct sockaddr_storage* client_addr, socklen_t client_addr_len, char* file_path, unsigned file_size) {
    FILE* file = fopen(file_path, "r");
    unsigned char* buffer = malloc(file_size);
    fread(buffer, sizeof(unsigned char), file_size, file);
    fclose(file);

    unsigned int offset = 0;
    while(offset < file_size) {
        send_file_packet(socket, client_addr, client_addr_len, offset, file_size, buffer);
        offset += FILE_DATA_SIZE;
    }

    struct rft_packet_file terminator_packet;
    terminator_packet.header = RFT_FILE;
    terminator_packet.offset = OFFSET_DONE;

    int tries = MAX_TRIES;
    while(tries--) {
        send_packet(socket, client_addr, client_addr_len, (void *) &terminator_packet);
        fprintf(stderr, "Sent terminator packet, tries left before giving up: %d\n", tries);

        struct rft_packet_resend* resend_packet = (struct rft_packet_resend*) wait_for_packet(socket, RFT_RESEND, NULL, NULL);

        if (resend_packet != NULL) {
            if (resend_packet->offset == OFFSET_DONE) {
                // client is done
                fprintf(stderr, "Client has confirmed that it's done\n");
                break;
            }
            send_file_packet(socket, client_addr, client_addr_len, resend_packet->offset, file_size, buffer);
            tries++; // a try doesn't count for timeout purposes unless we got nothing back from the client
        }
    }
}

void handle_request(int socket, struct sockaddr_storage* client_addr, socklen_t client_addr_len, struct rft_packet_request* request_packet) {
    struct stat file_stat;
    if (stat(request_packet->remote_path, &file_stat) != 0) {
        perror("handle_request stat");
        char* error_message = "File doesn't exist or is unreadable.";

        struct rft_packet_error error_packet;
        error_packet.header = RFT_ERROR;
        strncpy(error_packet.message, error_message, sizeof(error_packet.message));

        int tries = MAX_TRIES;
        while(tries--) {
            send_packet(socket, client_addr, client_addr_len, (void*) &error_packet);

            struct rft_packet_error* ack_error_packet = (struct rft_packet_error*) wait_for_packet(socket, RFT_ERROR_ACK, NULL, NULL);

            if (ack_error_packet != NULL) {
                // client acknowledged error
                fprintf(stderr, "Successfully notified client of error");
                break;
            }
        }
        return;
    }
    struct rft_packet_size packet;
    packet.header = RFT_SIZE;
    packet.file_size = (unsigned int)file_stat.st_size;

    int tries = MAX_TRIES;
    while(tries--) {
        send_packet(socket, client_addr, client_addr_len, (void*) &packet);

        struct rft_packet_send* ack_packet = (struct rft_packet_send*) wait_for_packet(socket, RFT_SEND, NULL, NULL);

        if (ack_packet != NULL) {
            // send the file
            send_file(socket, client_addr, client_addr_len, request_packet->remote_path, (unsigned int)file_stat.st_size);
            break;
        }
    }
}

// CLIENT-ONLY FUNCTIONS
int get_socket(char* server_ip, char* server_port, struct addrinfo** server_addrinfo) {
    int sockfd = NULL;
    struct addrinfo hints, *servinfo, *p;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(server_ip, server_port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo (server): %s\n", gai_strerror(rv));
        return 0;
    }

    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1) {
            continue;
        }

        break;
    }

    if (p == NULL || sockfd == NULL) {
        return 0;
    }

    struct timeval timeval;
    timeval.tv_sec = TIMEOUT;
    timeval.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeval, sizeof(timeval)) < 0) {
        perror("Couldn't set socket timeout");
    }

    *server_addrinfo = servinfo;
    return sockfd;
}

int request_file(int socket, struct addrinfo* server_addrinfo, char* remote_path) {
    if (strlen(remote_path) > PACKET_SIZE - sizeof(int)) { // 4 bytes for header
        fprintf(stderr, "Path too long (must be <= %u chars)", (unsigned int)(PACKET_SIZE - sizeof(int)));
        return 0;
    }

    struct rft_packet_request packet;
    packet.header = RFT_REQUEST;
    strncpy(packet.remote_path, remote_path, sizeof(packet.remote_path) - 1);
    packet.remote_path[sizeof(packet.remote_path) - 1] = 0; // ensure there's a null terminator

    return send_packet(socket, (struct sockaddr_storage*)server_addrinfo->ai_addr, server_addrinfo->ai_addrlen, (void*)&packet);
}

void build_offsets_list(off_t size, unsigned int* list, size_t list_count) {
    unsigned int offset = 0;
    int i = 0;
    while(offset < size && i < list_count) {
        list[i] = offset;
        offset += FILE_DATA_SIZE;
        i++;
    }
}

void mark_offset(unsigned int offset, unsigned int* list, unsigned int list_count) {
    for (int i=0; i<list_count; i++) {
        if (list[i] == offset) {
            list[i] = OFFSET_DONE; // this is an invalid offset anyway since total file size is constrained by 32 bit integer
        }
    }
}

void request_resend(int socket, struct addrinfo* server_addrinfo, unsigned int offset) {
    struct rft_packet_resend packet;
    packet.header = RFT_RESEND;
    packet.offset = offset;

    send_packet(socket, (struct sockaddr_storage*)server_addrinfo->ai_addr, server_addrinfo->ai_addrlen, (void*)&packet);
}

int request_resends(int socket, struct addrinfo* server_addrinfo, unsigned int* list, unsigned int list_count) {
    int count = 0;
    for (int i=0; i<list_count; i++) {
        if (list[i] != OFFSET_DONE) {
            request_resend(socket, server_addrinfo, list[i]);
            count++;
        }
    }
    return count;
}

unsigned char* download(int socket, struct addrinfo* server_addrinfo, unsigned int size, struct rft_packet_file* first_file_packet) {
    unsigned char* buffer = malloc(size);

    unsigned int list_count = (size / FILE_DATA_SIZE) + 1;
    unsigned int list[list_count];
    build_offsets_list(size, list, list_count);

    unsigned int cpylen = FILE_DATA_SIZE;
    if (first_file_packet->offset + FILE_DATA_SIZE > size) {
        cpylen = size - first_file_packet->offset;
    }
    memcpy(buffer + first_file_packet->offset, first_file_packet->data, cpylen);
    mark_offset(first_file_packet->offset, list, list_count);

    while(1) {
        struct rft_packet_file* file_packet = (struct rft_packet_file*) wait_for_packet(socket, RFT_FILE, NULL, NULL);

        if (file_packet != NULL) {
            // got another file packet
            if (file_packet->offset == OFFSET_DONE) {
                // server thinks it's the end
                // request resends of any missing
                if (request_resends(socket, server_addrinfo, list, list_count) == 0) {
                    // no resends needed, notify server we have the whole thing
					printf("File successfully received, telling server\n");
                    int tries = MAX_TRIES;
                    while(tries--) {
                        // again, not critical for server to get this, just try a few times as a courtesy
                        request_resend(socket, server_addrinfo, OFFSET_DONE);
                    }
                    // ...and we're done
                    break;
                }
            } else {
                cpylen = FILE_DATA_SIZE;
                if (first_file_packet->offset + FILE_DATA_SIZE > size) {
                    cpylen = size - first_file_packet->offset;
                }
                memcpy(buffer + file_packet->offset, file_packet->data, cpylen);
                mark_offset(file_packet->offset, list, list_count);
            }
        }
    }
    return buffer;
}

unsigned char* start_download(int socket, struct addrinfo* server_addrinfo, unsigned int size) {
    struct rft_packet_send ack_packet;
    ack_packet.header = RFT_SEND;
    ack_packet.file_size = size;

    int tries = MAX_TRIES;
    while(tries--) {
        send_packet(socket, (struct sockaddr_storage*) server_addrinfo->ai_addr, server_addrinfo->ai_addrlen, (void*)&ack_packet);

        struct rft_packet_file* file_packet = (struct rft_packet_file*) wait_for_packet(socket, RFT_FILE, NULL, NULL);

        if (file_packet != NULL) {
            // got first file packet, continue downloading
            return download(socket, server_addrinfo, size, file_packet);
        }
    }
}

// ENTRY POINTS
int main_server(int argc, char** argv) {
    char* server_port = argv[1];

    struct addrinfo* server_addrinfo;

    int socket = bind_socket(server_port, &server_addrinfo);
    if (! socket) {
        fprintf(stderr, "Couldn't bind socket");
    }

    while(1) {
        struct sockaddr_storage client_addr;
        socklen_t client_addr_len;
        unsigned char* packet = wait_for_packet(socket, RFT_REQUEST, &client_addr, &client_addr_len);
        if (packet != NULL) {
            handle_request(socket, &client_addr, client_addr_len, (struct rft_packet_request*)packet);
        }
    }
}

int main_client(int argc, char** argv) {
    char* server_ip = argv[1];
    char* server_port = argv[2];
    char* remote_path = argv[3];
    char* local_path = argv[4];

    struct addrinfo* server_addrinfo;

    int socket = get_socket(server_ip, server_port, &server_addrinfo);
    if (! socket) {
        fprintf(stderr, "Couldn't bind socket");
    }

    int timedout = 1;
    int tries = MAX_TRIES;
    while(tries--) {
        printf("Attempting to contact %s:%s\n", server_ip, server_port);
        request_file(socket, server_addrinfo, remote_path);
        struct rft_packet_size* response_packet = (struct rft_packet_size*)wait_for_packet(socket, RFT_SIZE, NULL, NULL);

        if (response_packet != NULL) {
            printf("Downloading %llu bytes\n", (unsigned long long int) response_packet->file_size);

            unsigned char* buffer;
            buffer = start_download(socket, server_addrinfo, response_packet->file_size);

            FILE* file = fopen(local_path, "w");
            fwrite(buffer, sizeof(unsigned char), response_packet->file_size, file);
            fclose(file);

            timedout = 0;
            break;
        }
    }
    if (timedout) {
        printf("No response from %s:%s\n", server_ip, server_port);
    }

    freeaddrinfo(server_addrinfo);

    return 0;
}

int main(int argc, char** argv) {
    if (argc == 2) {
        return main_server(argc, argv);
    } else if (argc == 5) {
        return main_client(argc, argv);
    } else {
        printf("Usage (server): %s <server_port>\n", argv[0]);
        printf("Usage (client): %s <server_ip> <server_port> <remote_path> <local_path>\n", argv[0]);
        return 0;
    }
}
