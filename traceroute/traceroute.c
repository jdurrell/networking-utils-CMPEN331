#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <arpa/inet.h>
#include <bits/sockaddr.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define RECV_BUFFER_SIZE 256
#define ITERATIONS_PER_TTL 3

struct SendPacket {
    struct udphdr udphdr;
    uint8_t payload[8];
};

struct Response {
    struct iphdr iphdr;
    // ICMP message format is the same for both 'Time Exceeded' and 'Port Unreachable' Messages.
    // User must check the type and code fields to know which.
    struct {
        struct icmphdr icmphdr;
        struct iphdr originalIpHdr;
        uint8_t originalBytes[8];
    } responseBody;
};

// Hardcoded constants for proof-of-concept.
uint16_t SOURCE_PORT = 3000;
uint16_t DEST_PORT = 32768 + 666;

void debugPrintBufferBytes(uint8_t* buffer, int len) {
    for (int i = 0; i < len; i++) {
        printf("%u ", buffer[i]);
    }
    printf("\n");
}

void debugPrintIpHeader(struct iphdr iphdr) {
    printf("tos: %u\n", iphdr.tos);
    printf("tot_len: %u\n", ntohs(iphdr.tot_len));
    printf("id: %u\n", ntohs(iphdr.id));
    printf("frag_off: %u\n", iphdr.frag_off);
    printf("ttl: %u\n", iphdr.ttl);
    printf("protocol: %u\n", iphdr.protocol);
    printf("checksum: %u\n", iphdr.check);
    uint8_t buf[4];
    memcpy(buf, &(iphdr.saddr), 4);
    printf("saddr: %u - %u.%u.%u.%u\n", iphdr.saddr, buf[0], buf[1], buf[2], buf[3]);
    memcpy(buf, &(iphdr.daddr), 4);
    printf("daddr: %u - %u.%u.%u.%u\n", iphdr.daddr, buf[0], buf[1], buf[2], buf[3]);
}

void debugPrintICMPInfo(struct icmphdr hdr) {
    printf("Type: %d\n", hdr.type);
    printf("Code: %d\n", hdr.code);
    printf("Id: %d\n", ntohs(hdr.un.echo.id));
    printf("Sequence Number: %d\n", ntohs(hdr.un.echo.sequence));
    printf("Checksum: %u\n", hdr.checksum);
}

uint64_t totalMicroseconds(struct timeval time) {
    return (((uint64_t)(time.tv_sec)) * 1000000) + (uint64_t)(time.tv_usec);
}

void printOutputLine(uint32_t addr, struct timeval send, struct timeval recv) {
    uint64_t latency = totalMicroseconds(recv) - totalMicroseconds(send);
    printf("%d.%d.%d.%d (%lu.%lums)   ",
        (ntohl(addr) & 0xFF000000) >> 24,
        (ntohl(addr) & 0x00FF0000) >> 16,
        (ntohl(addr) & 0x0000FF00) >> 8,
        (ntohl(addr) & 0x000000FF),
        latency / 1000,
        latency % 1000
    );
}

// Calculate the 16-bit checksum of the given byte array. RFC 1071.
uint16_t checksum(uint8_t* arr, int len) {
    uint64_t checksum = 0;

    // Add up all the bytes.
    for (int i = 0; i < len / 2; i++) {
        checksum += arr[0] + (arr[1] << 8);
        arr += 2;
    }

    // Add the final byte if the length is odd.
    if (len % 2) {
        checksum += arr[0];
    }

    // Add carry bits to the sum.
    while (checksum >> 16) {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }

    return (uint16_t) (~checksum);
}

struct SendPacket buildMessage() {
    struct SendPacket message;

    message.udphdr.source = htons(SOURCE_PORT);
    message.udphdr.dest = htons(DEST_PORT);
    message.udphdr.len = htons(sizeof(message));
    message.udphdr.check = 0;  // Tells the destination to ignore the checksum.

    // Build payload.
    for (int i = 0; i < sizeof(message.payload); i++) {
        message.payload[i] = i+1;
    }

    return message;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Invalid number of arguments provided. Usage: traceroute <address-or-hostname>\n");
        return 1;
    }

    struct timeval TIMEOUT = {1, 0};
    int error = 0;

    // Resolve hostname to IP address.
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;  // Only use IPv4 addresses for now.
    hints.ai_protocol = IPPROTO_ICMP;
    hints.ai_flags = 0;
    hints.ai_socktype = SOCK_RAW;
    struct addrinfo* addrinfo = NULL;
    error = getaddrinfo(argv[1], NULL, &hints, &addrinfo);
    if (error < 0) {
        printf("Error resolving hostname %s: %d (%s)\n", argv[1], error, strerror(error));
        return 1;
    } else if (addrinfo == NULL) {
        printf("No addresses found for given hostname %s.\n", argv[1]);
        return 1;
    }

    // Set up address struct.
    struct sockaddr_in destAddr;
    memset(&destAddr, 0, sizeof(destAddr));
    destAddr.sin_addr.s_addr = ((struct sockaddr_in*) addrinfo->ai_addr)->sin_addr.s_addr;

    // Create socket for sending UDP messages.
    int sendSockId = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sendSockId == -1) {
        printf("Error creating sender socket.\n");
        return 1;
    }

    // Set up receiver socket for ICP messages.
    int recvSockId = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (recvSockId == -1) {
        printf("Error creating receiver socket.\n");
        return 1;
    }
    error = setsockopt(recvSockId, SOL_SOCKET, SO_RCVTIMEO, &TIMEOUT, sizeof(TIMEOUT));
    if (error < 0) {
        printf("Failed to set receive socket option correctly: %d\n", errno);
        return 1;
    }

    struct SendPacket message = buildMessage();

    int ttl = 1;
    int numFinalResponses = 0;
    uint32_t raddr = 0;
    struct timeval sendTime;
    struct timeval recvTime;
    uint8_t buffer[RECV_BUFFER_SIZE];
    struct Response* response;
    response = (struct Response*) buffer;
    
    printf("Tracing route to %d.%d.%d.%d:\n",
            (ntohl(destAddr.sin_addr.s_addr) & 0xFF000000) >> 24,
            (ntohl(destAddr.sin_addr.s_addr) & 0x00FF0000) >> 16,
            (ntohl(destAddr.sin_addr.s_addr) & 0x0000FF00) >> 8,
            (ntohl(destAddr.sin_addr.s_addr) & 0x000000FF)
    );
    while ((numFinalResponses < ITERATIONS_PER_TTL) && (ttl < 30)) {        
        printf("Hop %d: ", ttl);

        for (int i = 0; i < ITERATIONS_PER_TTL; i++) {
            // Reset receiving structures.
            memset(buffer, 0, RECV_BUFFER_SIZE);

            // Set TTL for this iteration.
            error = setsockopt(sendSockId, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
            if (error < 0) {
                printf("Failed to set send socket option: %d\n", errno);
            }

            // Send message.
            int bytes = sendto(sendSockId, (void*)(&message), sizeof(message), 0, (struct sockaddr*)(&destAddr), sizeof(destAddr));
            gettimeofday(&sendTime, NULL);
            if (bytes < 0) {
                printf("Error sending message.\n");
                return 1;
            }

            // Attempt to receive message.
            bytes = recvfrom(recvSockId, buffer, RECV_BUFFER_SIZE, 0, NULL, NULL);
            gettimeofday(&recvTime, NULL);
            if ((bytes < 0) && (errno != EAGAIN)) {
                printf("Error receiving message: %d\n", errno);
                return 1;
            }

            if ((bytes < 0) && (errno == EAGAIN)) {
                printf("* * * (timeout reached), ");
            } else {
                raddr = (uint32_t) (response->iphdr.saddr);
                if (raddr == destAddr.sin_addr.s_addr) {
                    numFinalResponses++;
                }
                printOutputLine(raddr, sendTime, recvTime);
            }

            // Sleep for half a second in between packets.
            struct timespec sleepTime = {0, 500 * 1000 * 1000};
            nanosleep(&sleepTime, NULL);
        }
        printf("\n");

        // Increment ttl to discover next hop.
        ttl++;
    }

    if (raddr != destAddr.sin_addr.s_addr) {
        printf("Max TTL exceeded. Did not receive response from destination.\n");
    }

    return 0;
}