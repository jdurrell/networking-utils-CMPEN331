// Fix VSCode intellisense.
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "util.h"

#define ADDRESS_BUFFER_SIZE 200
#define PID_DATA_IDX 0
#define MAGIC_DATA_IDX 1
#define PID_UN_IDX 0
#define SEQUENCE_NUMBER_UN_IDX 1
#define SEND_BUFFER_SIZE 256
#define RECV_BUFFER_SIZE 256

struct EchoPacketV4 {
    struct icmphdr hdr;   // ICMP Header
    int data[2];          // Data containing magic values to help ensure correctness.
};
struct EchoResponseV4 {
    // Raw socket shows us the IP header on an incoming packet, even when we did not directly supply it for the outgoing packet.
    struct iphdr iphdr;
    struct EchoPacketV4 packet;
};

// In theory, the echo requests for ICMP and ICMPv6 are exactly the same (except for a different code).
// It is redefined here anyways for posterity.
struct EchoPacketV6 {
    struct icmp6_hdr hdr;   // ICMPv6 Header
    int data[2];            // Data containing magic values to help ensure correctness.
};
// Raw socket does not show us the IP header on an incoming packet for ICMPv6, unlike ICMP.
// Therefore, the EchoPacketV6 struct is simply re-used as the response struct.

uint8_t recvBuffer[RECV_BUFFER_SIZE];
int MAGIC = (13 << 24) + (0 << 16) + (94 << 8) + (35);
struct timeval TIMEOUT = {3, 0};  // Timeout of 3 seconds.
int error = 0;

void debugPrintPacketInfov4(struct EchoPacketV4 packet) {
    debugPrintICMPHeader(packet.hdr);
    printf("Data: %d %d\n", packet.data[0], packet.data[1]);
}

uint8_t verifyResponseV4(struct EchoResponseV4* reply, uint32_t daddr, uint16_t sequenceNumber, int pid) {
    /* Ensure reply message was correct:
     * read amount is at least the minimum size
     * is from the target
     * is an echo response
     * is a response to this iteration
     * is a response to this process
     * magic is correct
     */
    return (reply->iphdr.saddr == daddr)
            && (reply->packet.hdr.type == ICMP_ECHOREPLY) && (reply->packet.hdr.code == 0)
            && (reply->packet.hdr.un.echo.sequence == sequenceNumber)
            && (reply->packet.data[PID_DATA_IDX] == pid)
            && (reply->packet.data[MAGIC_DATA_IDX] == MAGIC);
}

// Verifies the given response to an echo message for IPv6. reply, returnAddr, and daddr must not be null.
uint8_t verifyResponseV6(
    struct EchoPacketV6* reply, struct sockaddr_in6* returnAddr, struct sockaddr_in6* daddr, uint16_t sequenceNumber, int pid)
{
    /* Ensure reply message was correct:
     * read amount is at least the minimum size
     * is from the target
     * is an echo response
     * is a response to this iteration
     * is a response to this process
     * magic is correct
     */
    return (ipv6AddressesAreEqual(returnAddr->sin6_addr, daddr->sin6_addr)
        && (reply->hdr.icmp6_code == 0) && (reply->hdr.icmp6_type == ICMP6_ECHO_REPLY)
        && (reply->hdr.icmp6_dataun.icmp6_un_data16[SEQUENCE_NUMBER_UN_IDX] == sequenceNumber)
        && (reply->data[PID_DATA_IDX] == pid)
        && (reply->data[MAGIC_DATA_IDX] == MAGIC));
  
}

int pingv4(struct addrinfo* addrinfo, int sockId) {

    // Set up address struct.
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = ((struct sockaddr_in*) addrinfo->ai_addr)->sin_addr.s_addr;
    addr.sin_family = AF_INET;
    char* ipAddressString = inet_ntoa(addr.sin_addr);

    // Build ICMP echo request message. RFCs 792 (v4) and 4443 (v6).
    struct EchoPacketV4 echoRequestMessage;
    echoRequestMessage.hdr.type = ICMP_ECHO;
    echoRequestMessage.hdr.code = 0;
    // Cast pid to a 16-bit integer because id field is 16-bit.
    echoRequestMessage.hdr.un.echo.id = htons((uint16_t)(getpid() % (1 << 16)));
    echoRequestMessage.hdr.un.echo.sequence = htons(1);
    echoRequestMessage.data[MAGIC_DATA_IDX] = MAGIC;
    echoRequestMessage.data[PID_DATA_IDX] = getpid();

    // Set up response fields.
    uint8_t recvBuffer[RECV_BUFFER_SIZE];
    struct EchoResponseV4* reply = (struct EchoResponseV4*) recvBuffer;
    struct icmphdr* replyHdr = &(reply->packet.hdr);
    struct timeval sendTime;
    struct timeval recvTime;

    printf("Pinging %s:\n", ipAddressString);
    while (true) {
        // Reset structures for receiving data.
        memset(recvBuffer, 0, RECV_BUFFER_SIZE);

        // Calculate checksum.
        echoRequestMessage.hdr.checksum = 0;
        echoRequestMessage.hdr.checksum = checksum((uint8_t*)(&echoRequestMessage), sizeof(echoRequestMessage));

        // Send echo request message.
        gettimeofday(&sendTime, NULL);
        int bytes = sendto(
                sockId, (uint8_t*)(&echoRequestMessage), sizeof(echoRequestMessage), 0, (struct sockaddr*)(&addr), sizeof(addr)
        );
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

        // Continuously attempt to receive echo reply message until we either receive the expected echo response or time out.
        while (true) {
            errno = 0;  // Reset flag because it may have been set by a previous timeout.
            bytes = recvfrom(sockId, recvBuffer, RECV_BUFFER_SIZE, 0, NULL, NULL);
            gettimeofday(&recvTime, NULL);
            if ((bytes < 0) && (errno != EAGAIN)) {
                printf("Error receiving message %d: (%s)\n",
                        ntohs(echoRequestMessage.hdr.un.echo.sequence), strerror(errno)
                );
                return 1;
            } else if (errno == EAGAIN) {
                // Timed out.
                printf("* * *\n");
                break;
            }

            if ((bytes >= sizeof(struct EchoResponseV4)) 
                && verifyResponseV4(reply, addr.sin_addr.s_addr, echoRequestMessage.hdr.un.echo.sequence, getpid()))
            {
                // Reply message was valid: print output to console.
                uint64_t latency = totalMicroseconds(recvTime) - totalMicroseconds(sendTime);
                printf("Reply %d from %s received in %ld.%ldms\n", 
                        ntohs(replyHdr->un.echo.sequence), ipAddressString, latency/1000, latency%1000
                );
                break;
            }
            // else, message was not valid, so try again.
        }

        // Sleep for a second so that we don't spam both the console and the target server.
        sleep(1);

        // Increment sequence number.
        echoRequestMessage.hdr.un.echo.sequence = htons(ntohs(echoRequestMessage.hdr.un.echo.sequence) + 1);
    }

    return 0;
}

int pingv6(struct addrinfo* addrinfo, int sockId) {
    // Set up address struct.
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_addr = ((struct sockaddr_in6*)(addrinfo->ai_addr))->sin6_addr;
    addr.sin6_family = AF_INET6;

    // Build ICMP echo request message. RFCs 792 (v4) and 4443 (v6).
    struct EchoPacketV6 echoRequestMessage;
    echoRequestMessage.hdr.icmp6_type = ICMP6_ECHO_REQUEST;
    echoRequestMessage.hdr.icmp6_code = 0;
    // Cast pid to a 16-bit integer because id field is 16-bit.
    echoRequestMessage.hdr.icmp6_dataun.icmp6_un_data16[PID_UN_IDX] = htons((uint16_t)(getpid() % (1 << 16)));
    echoRequestMessage.hdr.icmp6_dataun.icmp6_un_data16[SEQUENCE_NUMBER_UN_IDX] = htons(1);
    echoRequestMessage.data[PID_DATA_IDX] = getpid();
    echoRequestMessage.data[MAGIC_DATA_IDX] = MAGIC;

    // Set up response fields.
    uint8_t recvBuffer[RECV_BUFFER_SIZE];
    struct EchoPacketV6* reply = (struct EchoPacketV6*) recvBuffer;
    struct icmp6_hdr* replyHdr = &(reply->hdr);
    struct sockaddr_in6 returnAddr;
    int returnAddrLen = sizeof(returnAddr);
    struct timeval sendTime;
    struct timeval recvTime;

    char ipAddressString[ADDRESS_BUFFER_SIZE];
    inet_ntop(AF_INET6, &(addr.sin6_addr), ipAddressString, ADDRESS_BUFFER_SIZE);
    printf("Pinging %s:\n", ipAddressString);
    uint16_t sequenceNumber = 0;
    while (true) {
        echoRequestMessage.hdr.icmp6_dataun.icmp6_un_data16[SEQUENCE_NUMBER_UN_IDX] = sequenceNumber;
        
        // Reset structures for receiving data.
        memset(recvBuffer, 0, RECV_BUFFER_SIZE);

        // Calculate checksum.
        echoRequestMessage.hdr.icmp6_cksum = 0;
        echoRequestMessage.hdr.icmp6_cksum = checksum((uint8_t*)(&echoRequestMessage), sizeof(echoRequestMessage));

        // Send echo request message.
        gettimeofday(&sendTime, NULL);
        int bytes = sendto(
                sockId, (uint8_t*)(&echoRequestMessage), sizeof(echoRequestMessage), 0, (struct sockaddr*)(&addr), sizeof(addr)
        );
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

        // Continuously attempt to receive echo reply message until we either receive the expected echo response or time out.
        while (true) {
            errno = 0;
            bytes = recvfrom(sockId, recvBuffer, RECV_BUFFER_SIZE, 0, (struct sockaddr*)(&returnAddr), &returnAddrLen);
            gettimeofday(&recvTime, NULL);
            if ((bytes < 0) && (errno != EAGAIN)) {
                printf("Error receiving message %d: (%s)\n",
                        ntohs(echoRequestMessage.hdr.icmp6_dataun.icmp6_un_data16[SEQUENCE_NUMBER_UN_IDX]), strerror(errno)
                );
                return 1;
            } else if (errno == EAGAIN) {
                // Timed out.
                printf("* * *\n");
                break;
            }

            if ((bytes >= sizeof(struct EchoPacketV6)) && verifyResponseV6(reply, &returnAddr, &addr, sequenceNumber, getpid())) {
                // Reply message was valid: print output to console.
                uint64_t latency = totalMicroseconds(recvTime) - totalMicroseconds(sendTime);
                printf("Reply %d from %s received in %ld.%ldms\n", 
                        replyHdr->icmp6_dataun.icmp6_un_data16[SEQUENCE_NUMBER_UN_IDX],
                        ipAddressString, latency/1000, latency%1000
                );
                break;
            }
            // else, message was not valid, so try again.
        }

        // Increment sequence number.
        sequenceNumber++;

        // Sleep for a second so that we don't spam both the console and the target server.
        sleep(1);
    }

    return 0;
}

int main(int argc, char* argv[]) {
    if ((argc < 2) || (argc > 3)) {
        printf("Invalid arguments provided. Usage: ping <target> -[46]\n");
        return 1;
    }

    // Parse command line options.
    char* target = argv[1];
    int version = 4;  // Default to using IPv4.
    int opt;
    while ((opt = getopt(argc, argv, "46")) != -1) {
        switch (opt) {
        case '4':
            version = 4;
            break;
        case '6':
            version = 6;
            break;
        default:
            printf("Usage: %s [target] [-(4|6) version]\n", argv[0]);
            return 1;
        }
    }

    struct addrinfo* addrinfo = resolveHostnameOrIP(target, version);
    if (addrinfo == NULL) {
        printf("Host resolution failed.\n");
        if (version == 4 && strchr(argv[1], ':') != NULL) {
            printf("Did you mean to include the -6 flag?\n");
        }
        return 1;
    }

    // Create raw socket for sending and receiving ICMP messages.
    int sockId;
    if (version == 4) {
        sockId = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); 
    } else {
        sockId = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    }
    if (sockId == -1) {
        printf("Error creating socket.\n");
        return 1;
    }
    error = setsockopt(sockId, SOL_SOCKET, SO_RCVTIMEO, &TIMEOUT, sizeof(TIMEOUT));
    if (error < 0) {
        printf("Failed to set receive socket option correctly: %s\n", strerror(errno));
        return 1;
    }


    if (version == 4) {
        return pingv4(addrinfo, sockId);
    } else {
        return pingv6(addrinfo, sockId);
    }

    return 0;
}
