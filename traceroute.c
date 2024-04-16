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
#include <stdbool.h>
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
#define UDP_PAYLOAD_LENGTH 8
#define ID_PID_MASK 0xFF00
#define ID_TTL_MASK 0x00FF

uint16_t SOURCE_PORT = 3000;
// uint16_t DEST_PORT = 32768 + 666;
uint16_t DEST_PORT = 33434;

struct SendPacket {
    struct iphdr iphdr;
    struct udphdr udphdr;
    uint8_t payload[UDP_PAYLOAD_LENGTH];
};

struct Response {
    struct iphdr iphdr;
    // ICMP message format is the same for both 'Time Exceeded' and 'Port Unreachable' Messages.
    // User must check the type and code fields to know which.
    struct {
        struct icmphdr icmphdr;
        struct iphdr originalIpHdr;
        int originalPayload[2];
    } responseBody;
};

int pid;

// Print the output for one packet.
void printTracerouteOutput(uint32_t addr, struct timeval send, struct timeval recv) {
    uint64_t latency = totalMicroseconds(recv) - totalMicroseconds(send);
    printf("%s (%lu.%lums)   ",
        inet_ntoa(*((struct in_addr*)(&addr))),  // Dirty cast from 32-bit address to proper 32-bit struct.
        latency / 1000,
        latency % 1000
    );
}

uint16_t pidAlignedToMask(int pid) {
    return (uint16_t) ((pid & 0xFF) << 16);
}

uint8_t verifyValidResponse(struct Response* reply, struct in_addr* target, int pid, int ttl) {
    // Fail if reponse was intended for a different cycle or pid doesn't match closely enough.
    struct iphdr* originalIpHdr = &(reply->responseBody.originalIpHdr);
    if (((originalIpHdr->id & ID_TTL_MASK) != ttl) || ((originalIpHdr->id & ID_PID_MASK) != pidAlignedToMask(pid))) {
        return false;
    }

    // If reply was a 'port unreachable' response, then succeed only if the destination address matches the target.
    if ((reply->responseBody.icmphdr.type == ICMP_UNREACH) && (reply->responseBody.icmphdr.code == ICMP_UNREACH_PORT)) {
        return target->s_addr == reply->iphdr.saddr;
    }

    // If reply was a 'ttl exceeded' response, then this is a valid response.
    if ((reply->responseBody.icmphdr.type == ICMP_TIMXCEED) && (reply->responseBody.icmphdr.code == ICMP_EXC_TTL)) {
        return true;
    }

    // Otherwise, the message was invalid.
    return false;
}

// Build the probe to send.
struct SendPacket buildMessage(uint32_t daddr) {
    struct SendPacket message;

    message.iphdr.daddr = daddr;
    message.iphdr.frag_off = htons(1 << 14);  // Set the 'don't fragment' flag.
    // Id field gets returned to us, so we can use it for later response validation.
    // It holds TTL in the lower 8 bits and pid mod 256 in the upper 8 bits.
    message.iphdr.id = pidAlignedToMask(pid);
    message.iphdr.ihl = 5;  // 20 bytes
    message.iphdr.protocol = IPPROTO_UDP;
    message.iphdr.saddr = 0;  // This will be set later by the sendto call.
    message.iphdr.tos = 0;
    message.iphdr.tot_len = sizeof(message);
    message.iphdr.ttl = 0;    // This will be set later by the sendto call.
    message.iphdr.version = 4;  // IPv4
    message.iphdr.check = checksum((uint8_t*)(&message.iphdr), sizeof(struct iphdr));

    message.udphdr.source = htons(SOURCE_PORT);
    message.udphdr.dest = htons(DEST_PORT);
    message.udphdr.len = htons(sizeof(message) - sizeof(struct iphdr));
    message.udphdr.check = 0;  // Tells the destination to ignore the checksum.

    // Build payload.
    for (int i = 0; i < UDP_PAYLOAD_LENGTH; i++) {
        message.payload[i] = i+1;
    }

    return message;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Invalid number of arguments provided. Usage: traceroute <address-or-hostname>\n");
        return 1;
    }

    char* target = argv[1];
    pid = getpid();
    struct timeval TIMEOUT = {1, 0};
    int error = 0;

    // Set up address struct.
    struct addrinfo* addrinfo = resolveHostnameOrIP(target, 4);  // Only supporting IPv4 addresses for now.
    if (addrinfo == NULL) {
        printf("Host resolution failed.\n");
        return 1;
    }
    struct sockaddr_in destAddr = *((struct sockaddr_in*)(addrinfo->ai_addr));
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = DEST_PORT;
    freeaddrinfo(addrinfo);

    // Create socket for sending UDP messages.
    int sendSockId = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sendSockId == -1) {
        printf("Error creating sender socket: %s\n", strerror(errno));
        return 1;
    }
    int on = 1;
    error = setsockopt(sendSockId, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    if (error < 0) {
        printf("Error setting end-socket header-incl: %s\n", strerror(errno));
    }

    // Set up receiver socket for ICP messages.
    int recvSockId = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (recvSockId == -1) {
        printf("Error creating receiver socket: %s\n", strerror(errno));
        return 1;
    }
    error = setsockopt(recvSockId, SOL_SOCKET, SO_RCVTIMEO, &TIMEOUT, sizeof(TIMEOUT));
    if (error < 0) {
        printf("Failed to set receive socket timeout option: %s\n", strerror(errno));
        return 1;
    }

    struct SendPacket message = buildMessage(destAddr.sin_addr.s_addr);

    uint16_t ttl = 1;
    int numFinalResponses = 0;
    uint32_t raddr = 0;
    uint8_t recvBuffer[RECV_BUFFER_SIZE];

    printf("Tracing route to %s (%s):\n", inet_ntoa(destAddr.sin_addr), target);
    while ((numFinalResponses < ITERATIONS_PER_TTL) && (ttl < 30)) {        
        printf("Hop\t%d: ", ttl);
        struct timeval sendTime;
        struct timeval recvTime;
        struct Response* response = (struct Response*) recvBuffer;

        // Set TTL for this iteration.
        message.iphdr.id = (message.iphdr.id & ~ID_TTL_MASK) | ttl;  // Pack TTL into the id for later response verification.
        message.iphdr.ttl = ttl;
        error = setsockopt(sendSockId, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        if (error < 0) {
            printf("Failed to set send socket TTL option: %s\n", strerror(errno));
            return 1;
        }
        for (int i = 0; i < ITERATIONS_PER_TTL; i++) {
            // Reset receiving structures.
            memset(recvBuffer, 0, RECV_BUFFER_SIZE);

            // Send message.
            int bytes = sendto(sendSockId, &message, sizeof(message), 0, (struct sockaddr*)(&destAddr), sizeof(destAddr));
            gettimeofday(&sendTime, NULL);
            if (bytes < 0) {
                printf("Error sending message.\n");
                return 1;
            }

            // Continuously attempt to receive reply messages until we either receive the expected responses or time out.
            while (true) {
                bytes = recvfrom(recvSockId, recvBuffer, RECV_BUFFER_SIZE, 0, NULL, NULL);
                // printf("Received %d bytes for ttl %d\n", bytes, ttl);
                gettimeofday(&recvTime, NULL);
                if ((bytes < 0) && (errno != EAGAIN)) {
                    printf("Error receiving message: %d\n", errno);
                    return 1;
                }

                if ((bytes < 0) && (errno == EAGAIN)) {
                    // Timed out.
                    printf("* * * (timeout reached), ");
                    break;
                }

                if ((bytes >= sizeof(struct Response))
                    && verifyValidResponse(response, &(destAddr.sin_addr), pid, ttl)
                ) {
                    raddr = (uint32_t) (response->iphdr.saddr);
                    if (raddr == destAddr.sin_addr.s_addr) {
                        numFinalResponses++;
                    }
                    printTracerouteOutput(raddr, sendTime, recvTime);
                    break;
                }
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