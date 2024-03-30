#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define RECV_BUFFER_SIZE 256

struct SendPacket {
    struct udphdr udphdr;
    uint8_t payload[8];
};

struct TimeExceededResponse {
    struct iphdr iphdr;
    struct {
        struct icmphdr icmphdr;
        struct iphdr originalIpHdr;
        uint8_t originalBytes[8];
    } responseBody;
};

// Hardcoded constants for proof-of-concept.
uint32_t GOOGLE_IP_ADDRESS = (8 << 24) + (8 << 16) + (8 << 8) + (8);
uint32_t MAGIC = (13 << 24) + (0 << 16) + (94 << 8) + (35);
uint16_t SOURCE_PORT = 53;
uint16_t DEST_PORT = 60321;

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
    message.udphdr.check = 0;  // I *think* this have the destination ignore the checksum.

    // Build payload.
    for (int i = 0; i < sizeof(message.payload); i++) {
        message.payload[i] = i+1;
    }

    return message;
}

int main() {
    struct timeval TIMEOUT = {1, 0};
    int error = 0;

    // Set up address struct.
    struct sockaddr_in destAddr;
    destAddr.sin_addr.s_addr = GOOGLE_IP_ADDRESS;

    // Create socket for sending UDP messages.
    int sendSockId = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sendSockId == -1) {
        printf("Error creating sender socket.\n");
        return 1;
    }

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
    // uint8_t msgbuffer[8];
    // memset(msgbuffer, 0, sizeof(msgbuffer));
    // memcpy(msgbuffer, &MAGIC, sizeof(MAGIC));

    int ttl = 2;
    uint32_t raddr = 0;
    uint8_t buffer[RECV_BUFFER_SIZE];
    while ((raddr != GOOGLE_IP_ADDRESS) && (ttl < 30)) {        
        memset(buffer, 0, RECV_BUFFER_SIZE);
        error = setsockopt(sendSockId, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        if (error < 0) {
            printf("Failed to set send socket option: %d\n", errno);
        }

        int bytes = sendto(sendSockId, (void*)(&message), sizeof(message), 0, (struct sockaddr*)(&destAddr), sizeof(destAddr));
        if (bytes < 0) {
            printf("Error sending message.\n");
            return 1;
        }
        printf("\nSent message with ttl %d\n", ttl);
        ttl++;

        struct sockaddr_in returnAddr;
        uint32_t returnAddrSize = sizeof(returnAddr);
        bytes = recvfrom(recvSockId, buffer, RECV_BUFFER_SIZE, 0, (struct sockaddr*)(&returnAddr), &(returnAddrSize));
        if ((bytes < 0) && (errno != EAGAIN)) {
            printf("Error receiving message: %d\n", errno);
            return 1;
        }
        printf("Received %d bytes.\n", bytes);

        if ((bytes < 0) && (errno == EAGAIN)) {
            printf("Timeout reached. No response received.\n");
        } else {
            struct TimeExceededResponse* response;
            response = (struct TimeExceededResponse*) buffer;
            raddr = (uint32_t) response->iphdr.saddr;
            debugPrintBufferBytes(buffer, bytes);
            printf("\nMessage Header:\n");
            debugPrintIpHeader(response->iphdr);
            printf("\nICMP Header:\n");
            debugPrintICMPInfo(response->responseBody.icmphdr);
            printf("\nOriginal message header:\n");
            debugPrintIpHeader(response->responseBody.originalIpHdr);
            printf("\nOriginal message bytes:\n");
            debugPrintBufferBytes((uint8_t*)(&(response->responseBody.originalBytes)), 8);
        }
    }

    return 0;
}