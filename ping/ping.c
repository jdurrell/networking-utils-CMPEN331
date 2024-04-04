#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <arpa/inet.h>
#include <bits/sockaddr.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define RECV_BUFFER_SIZE 256

struct EchoPacket {
    struct icmphdr hdr;   // ICMP Header
    uint8_t data[8];      // Data containing magic value to help ensure correctness.
};

struct EchoResponse {
    struct iphdr iphdr;
    struct EchoPacket packet;
};

void debugPrintPacketInfo(struct EchoPacket packet) {
    printf("Type: %d\n", packet.hdr.type);
    printf("Code: %d\n", packet.hdr.code);
    printf("Id: %d\n", ntohs(packet.hdr.un.echo.id));
    printf("Sequence Number: %d\n", ntohs(packet.hdr.un.echo.sequence));
    printf("Checksum: %u\n", packet.hdr.checksum);
    printf("Data: %lu\n", *((uint64_t*)(packet.data)));
}

void debugPrintBufferBytes(uint8_t* buffer, int len) {
    for (int i = 0; i < len; i++) {
        printf("%u ", buffer[i]);
    }
    printf("\n");
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

int main(int argc, char* argv[]) {
    int MAGIC = (13 << 24) + (0 << 16) + (94 << 8) + (35);

    if (argc != 2) {
        printf("Invalid number of arguments provided. Usage: ping <address-or-hostname>\n");
        return 1;
    }

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
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = ((struct sockaddr_in*) addrinfo->ai_addr)->sin_addr.s_addr;
    printf("IP address to ping: %d.%d.%d.%d\n",
            (ntohl(addr.sin_addr.s_addr) & 0xFF000000) >> 24,
            (ntohl(addr.sin_addr.s_addr) & 0x00FF0000) >> 16,
            (ntohl(addr.sin_addr.s_addr) & 0x0000FF00) >> 8,
            (ntohl(addr.sin_addr.s_addr) & 0x000000FF)
    );

    // Create raw socket for sending and receiving ICMP messages.
    int sockId = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockId == -1) {
        printf("Error creating socket.\n");
        return 1;
    }

    // Build ICMP echo request message. RFC 792.
    struct EchoPacket echoRequestMessage;
    echoRequestMessage.hdr.type = ICMP_ECHO;
    echoRequestMessage.hdr.code = 0;
    uint16_t message_id = (uint16_t)(getpid() % (1 << 16));  // Cast pid to a 16-bit integer to store it in the id field.
    echoRequestMessage.hdr.un.echo.id = htons(getpid());
    echoRequestMessage.hdr.un.echo.sequence = htons(0);
    int* data = (int*) (echoRequestMessage.data);
    data[0] = MAGIC;
    data[1] = getpid();

    // Set up response fields.
    uint8_t buffer[RECV_BUFFER_SIZE];
    struct sockaddr_in returnAddress;
    uint32_t returnAddressSize = sizeof(returnAddress);
    struct EchoResponse* reply;
    reply = (struct EchoResponse*) buffer;

    while (true) {
        // Reset structures for receiving data.
        memset(buffer, 0, RECV_BUFFER_SIZE);
        returnAddress.sin_addr.s_addr = 0;

        // Calculate checksum.
        echoRequestMessage.hdr.checksum = 0;
        echoRequestMessage.hdr.checksum = checksum((uint8_t*)(&echoRequestMessage), sizeof(echoRequestMessage));

        // Send echo request message.
        time_t sendTime = time(NULL);
        int bytes = sendto(sockId, &(echoRequestMessage), sizeof(echoRequestMessage), 0, (struct sockaddr*)(&addr), sizeof(addr));
        if (bytes < 0) {
            printf("Error sending message: %d (%s)\n", errno, strerror(errno));
            return 1;
        } else if (bytes != sizeof(echoRequestMessage)) {
            printf(
                    "Error: Did not send the expected number of bytes. Expected %lu, sent %d.\n",
                    sizeof(echoRequestMessage), bytes
            );
            return 1;
        }
        // printf("Sent %d bytes.\n", bytes);

        // Attempt to receive echo reply message.
        bytes = recvfrom(sockId, buffer, RECV_BUFFER_SIZE, 0, (struct sockaddr*)(&returnAddress), &(returnAddressSize));
        time_t latency = time(NULL) - sendTime;
        if (bytes < 0) {
            printf("Error receiving message: %d (%s)\n", errno, strerror(errno));
            return 1;
        } else if (bytes != sizeof(struct EchoResponse)) {
            printf(
                    "Error: Did not receive the expected number of bytes. Expected %lu, received %d.\n",
                    sizeof(struct EchoResponse), bytes
            );
            return 1;
        }
        // printf("Received %d bytes.\n", bytes);

        // Parse reply message.
        struct icmphdr* replyHdr = &(reply->packet.hdr);
        if ((returnAddress.sin_addr.s_addr == addr.sin_addr.s_addr)                     // Packet is from the target.
            && (replyHdr->code == 0) && (replyHdr->type == 0)                           // Packet is an echo response.
            && (replyHdr->un.echo.sequence == echoRequestMessage.hdr.un.echo.sequence)  // Packet is a response to this iteration.
            && (((int*)(&(reply->packet.data)))[1] == getpid()))                        // Packet is a response to *this* process.
        {
            printf("\n");
            debugPrintPacketInfo(reply->packet);
        }

        // Increment sequence number.
        echoRequestMessage.hdr.un.echo.sequence = ntohs(htons(echoRequestMessage.hdr.un.echo.sequence) + 1);

        // Sleep for a second so that we don't spam both the console and the target server.
        sleep(1);
    }

    return 0;
}
