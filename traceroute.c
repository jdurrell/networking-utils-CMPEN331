// Fix VSCode intellisense.
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
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

#include "util.h"

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

void printTracerouteOutputLine(uint32_t addr, struct timeval send, struct timeval recv) {
    uint64_t latency = totalMicroseconds(recv) - totalMicroseconds(send);
    printf("%s (%lu.%lums)   ",
        inet_ntoa(*((struct in_addr*)(&addr))),  // Dirty cast from 32-bit address to proper 32-bit struct.
        latency / 1000,
        latency % 1000
    );
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

    struct addrinfo* addrinfo = resolveHostnameOrIP(argv[1], 4);  // Only supporting IPv4 addresses for now.
    if (addrinfo == NULL) {
        printf("Host resolution failed.\n");
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
                printTracerouteOutputLine(raddr, sendTime, recvTime);
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