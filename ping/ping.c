#include <arpa/inet.h>
#include <bits/sockaddr.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>


// #include "utils/utils.h"

struct packet {
    struct icmphdr hdr;   // ICMP Header
    uint8_t data[8];      // Data containing magic value to help ensure correctness.
};

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

int main() {
    // Hardcoded constants for proof-of-concept.
    uint32_t GOOGLE_IP_ADDRESS = (8 << 24) + (8 << 16) + (8 << 8) + (8);
    uint64_t MAGIC = (13 << 24) + (0 << 16) + (94 << 8) + (35);
    printf("Magic value: %lu\n", MAGIC);


    // Set up address struct.
    struct sockaddr_in addr;
    addr.sin_addr.s_addr = GOOGLE_IP_ADDRESS;

    // Create raw socket.
    int sockId = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockId == -1) {
        printf("Error creating socket.\n");
        return 1;
    }

    // Build ICMP echo request message. RFC 792.
    struct packet echoRequestMessage;
    echoRequestMessage.hdr.type = ICMP_ECHO;
    echoRequestMessage.hdr.code = 0;
    echoRequestMessage.hdr.un.echo.id = htons(getpid());
    echoRequestMessage.hdr.un.echo.sequence = htons(0);
    memcpy(echoRequestMessage.data, &MAGIC, sizeof(echoRequestMessage.data));
    echoRequestMessage.hdr.checksum = checksum((uint8_t*)(&echoRequestMessage), sizeof(echoRequestMessage));

    // Send echo request message.
    uint32_t bytes = sendto(sockId, &(echoRequestMessage), sizeof(echoRequestMessage), 0, (struct sockaddr*)(&addr), sizeof(addr));
    printf("Sent %u bytes.\n", bytes);

    // Receive echo reply message.
    uint8_t buffer[256];
    struct sockaddr_in returnAddress;
    uint32_t returnAddressSize = sizeof(returnAddress);
    bytes = recvfrom(sockId, buffer, sizeof(echoRequestMessage), 0, (struct sockaddr*)(&returnAddress), &(returnAddressSize));
    printf("Received %u bytes.\n", bytes);

    // Parse reply message.
    struct packet reply;
    memcpy(&reply, buffer, sizeof(reply));
    printf("Type: %d\n", reply.hdr.type);
    printf("Code: %d\n", reply.hdr.code);
    printf("Id: %d\n", reply.hdr.un.echo.id);
    printf("Sequence Number: %d\n", reply.hdr.un.echo.sequence);
    printf("Checksum: %u\n", reply.hdr.checksum);
    printf("Data: %lu\n", (uint64_t)(reply.data[0]));
}
