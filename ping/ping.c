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
#include <sys/time.h>
#include <sys/types.h>
// #include <time.h>
#include <unistd.h>

#define ADDRESS_BUFFER_SIZE 200
#define MAGIC_DATA_IDX 0
#define PID_DATA_IDX 1
#define RECV_BUFFER_SIZE 256

struct EchoPacket {
    struct icmphdr hdr;   // ICMP Header
    int data[2];         // Data containing magic values to help ensure correctness.
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

uint64_t totalMicroseconds(struct timeval time) {
    return (((uint64_t)(time.tv_sec)) * 1000000) + (uint64_t)(time.tv_usec);
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
    struct timeval TIMEOUT = {3, 0};
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
    char ipAddressString[ADDRESS_BUFFER_SIZE];
    snprintf(ipAddressString, ADDRESS_BUFFER_SIZE, "%d.%d.%d.%d",
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
    error = setsockopt(sockId, SOL_SOCKET, SO_RCVTIMEO, &TIMEOUT, sizeof(TIMEOUT));
    if (error < 0) {
        printf("Failed to set receive socket option correctly: %d\n", errno);
        return 1;
    }

    // Build ICMP echo request message. RFC 792.
    struct EchoPacket echoRequestMessage;
    echoRequestMessage.hdr.type = ICMP_ECHO;
    echoRequestMessage.hdr.code = 0;
    // Cast pid to a 16-bit integer because id field is 16-bit.
    echoRequestMessage.hdr.un.echo.id = htons((uint16_t)(getpid() % (1 << 16)));
    echoRequestMessage.hdr.un.echo.sequence = htons(1);
    echoRequestMessage.data[MAGIC_DATA_IDX] = MAGIC;
    echoRequestMessage.data[PID_DATA_IDX] = getpid();

    // Set up response fields.
    uint8_t buffer[RECV_BUFFER_SIZE];
    struct EchoResponse* reply;
    reply = (struct EchoResponse*) buffer;
    struct icmphdr* replyHdr = &(reply->packet.hdr);
    struct timeval sendTime;
    struct timeval recvTime;

    printf("Pinging %s:\n", ipAddressString);
    while (true) {
        // Reset structures for receiving data.
        memset(buffer, 0, RECV_BUFFER_SIZE);

        // Calculate checksum.
        echoRequestMessage.hdr.checksum = 0;
        echoRequestMessage.hdr.checksum = checksum((uint8_t*)(&echoRequestMessage), sizeof(echoRequestMessage));

        // Send echo request message.
        gettimeofday(&sendTime, NULL);
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

        // Attempt to receive echo reply message.
        bytes = recvfrom(sockId, buffer, RECV_BUFFER_SIZE, 0, NULL, NULL);
        gettimeofday(&recvTime, NULL);
        if ((bytes < 0) && (errno != EAGAIN)) {
            printf("Error receiving message %d: %d (%s)\n", echoRequestMessage.hdr.un.echo.sequence, errno, strerror(errno));
            return 1;
        } else if ((bytes > 0) && (bytes != sizeof(struct EchoResponse))) {
            printf(
                    "Error: Did not receive the expected number of bytes. Expected %lu, received %d.\n",
                    sizeof(struct EchoResponse), bytes
            );
            return 1;
        } else if (errno == EAGAIN) {
            // Timed out.
            printf("* * *\n");
        } else {
            // Ensure reply message was correct.
            if ((reply->iphdr.saddr == addr.sin_addr.s_addr)                                // Packet is from the target.
                && (replyHdr->code == 0) && (replyHdr->type == 0)                           // Packet is an echo response.
                && (replyHdr->un.echo.sequence == echoRequestMessage.hdr.un.echo.sequence)  // Packet is a response to this iteration.
                && (reply->packet.data[PID_DATA_IDX] == getpid())                           // Packet is a response to *this* process.
                && (reply->packet.data[MAGIC_DATA_IDX] == MAGIC))                           // Magic is correct.
            {
                // Reply message was valid: print output to console.
                uint64_t latency = totalMicroseconds(recvTime) - totalMicroseconds(sendTime);
                printf("Reply %d from %s received in %ld.%ldms\n", 
                        ntohs(replyHdr->un.echo.sequence), ipAddressString, latency/1000, latency%1000
                );
            } else {
                printf("* * *\n");
            }
        }

        // Increment sequence number.
        echoRequestMessage.hdr.un.echo.sequence = ntohs(htons(echoRequestMessage.hdr.un.echo.sequence) + 1);

        // Sleep for a second so that we don't spam both the console and the target server.
        sleep(1);
    }

    return 0;
}
