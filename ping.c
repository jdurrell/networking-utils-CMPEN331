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
#define SEND_BUFFER_SIZE 64
#define RECV_BUFFER_SIZE 256
#define IPV4_STRING_MAX_SIZE 16
#define IPV6_STRING_MAX_SIZE 40

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

uint8_t verifyResponse(
    int version, void* reply, uint16_t sequenceNumber, struct sockaddr_storage* daddr, struct sockaddr_storage* returnAddr)
{
    /* Ensure reply message was correct:
     * read amount is at least the minimum size
     * is from the target
     * is an echo response
     * is a response to this iteration
     * is a response to this process
     * magic is correct
     */
    if (version == 4) {
        struct EchoResponseV4* replyV4 = (struct EchoResponseV4*) reply;
        return (replyV4->iphdr.saddr == ((struct sockaddr_in*) daddr)->sin_addr.s_addr)
            && (replyV4->packet.hdr.type == ICMP_ECHOREPLY) && (replyV4->packet.hdr.code == 0)
            && (replyV4->packet.hdr.un.echo.sequence == sequenceNumber)
            && (replyV4->packet.data[PID_DATA_IDX] == getpid())
            && (replyV4->packet.data[MAGIC_DATA_IDX] == MAGIC);
    } else {
        struct EchoPacketV6* replyV6 = (struct EchoPacketV6*) reply;
        return (ipv6AddressesAreEqual(((struct sockaddr_in6*) returnAddr)->sin6_addr, ((struct sockaddr_in6*) daddr)->sin6_addr))
            && (replyV6->hdr.icmp6_type == ICMP6_ECHO_REPLY) && (replyV6->hdr.icmp6_code == 0)
            && (replyV6->hdr.icmp6_dataun.icmp6_un_data16[SEQUENCE_NUMBER_UN_IDX] == sequenceNumber)
            && (replyV6->data[PID_DATA_IDX] == getpid())
            && (replyV6->data[MAGIC_DATA_IDX] == MAGIC);
    }
}

// Build the sockaddr and (optionally) the string version of the IP address for the given host and protocol version.
// outSockaddr must not be null.
// outIpAddressString may be null.
// Returns -1 on error and 0 otherwise.
int buildSockaddr(int version, char* host, struct sockaddr_storage* outSockaddr, char** outIpAddressString) {
    struct addrinfo* addrinfo = resolveHostnameOrIP(host, version);
    if (addrinfo == NULL) {
        printf("Host resolution failed.\n");
        if (version == 4 && strchr(host, ':') != NULL) {
            printf("Did you mean to include the -6 flag?\n");
        }
        return -1;
    }

    if (version == 4) {
        struct sockaddr_in* outSockaddr_in = (struct sockaddr_in*) outSockaddr;
        (*outSockaddr_in).sin_addr = ((struct sockaddr_in*)(addrinfo->ai_addr))->sin_addr;
        (*outSockaddr_in).sin_family = AF_INET;
        (*outSockaddr_in).sin_port = 0;
        if (outIpAddressString != NULL) {
            *outIpAddressString = calloc(1, IPV4_STRING_MAX_SIZE);
            inet_ntop(AF_INET, &(outSockaddr_in->sin_addr), *outIpAddressString, IPV4_STRING_MAX_SIZE);
        }
    } else {
        struct sockaddr_in6* outSockaddr_in6 = (struct sockaddr_in6*) outSockaddr;
        memset(outSockaddr_in6, 0, sizeof(*outSockaddr_in6));
        (*outSockaddr_in6).sin6_addr = ((struct sockaddr_in6*)(addrinfo->ai_addr))->sin6_addr;
        (*outSockaddr_in6).sin6_family = AF_INET6;
        // (*outSockaddr_in6).sin6_port = 0;
        // (*outSockaddr_in6).sin6_scope_id = 0;
        // (*outSockaddr_in6).sin6_flowinfo = 0;
        if (outIpAddressString != NULL) {
            *outIpAddressString = calloc(1, IPV6_STRING_MAX_SIZE);
            inet_ntop(AF_INET6, &(outSockaddr_in6->sin6_addr), *outIpAddressString, IPV6_STRING_MAX_SIZE);
        }
    }

    return 0;
}

// Builds the probe for the echo request message for the given ip version.
// buffer and outMessageSize parameters must not be null.
// outResponseSize parameter may be null.
void buildEchoMessage(int version, void* buffer, uint32_t* outMessageSize, uint32_t* outResponseSize) {
    if (version == 4) {
        // Build ICMP echo request message. RFC 792.
        struct EchoPacketV4* echoRequestMessage = (struct EchoPacketV4*) buffer;
        echoRequestMessage->hdr.type = ICMP_ECHO;
        echoRequestMessage->hdr.code = 0;
        echoRequestMessage->hdr.un.echo.id = 0;
        echoRequestMessage->hdr.un.echo.sequence = htons(1);
        echoRequestMessage->data[PID_DATA_IDX] = getpid();
        echoRequestMessage->data[MAGIC_DATA_IDX] = MAGIC;
        *outMessageSize = sizeof(struct EchoPacketV4);
        if (outResponseSize != NULL) {
            *outResponseSize = sizeof(struct EchoResponseV4);
        }
    } else {
        // Build ICMP echo request message. RFC 4443.
        struct EchoPacketV6* echoRequestMessage = (struct EchoPacketV6*) buffer;
        echoRequestMessage->hdr.icmp6_type = ICMP6_ECHO_REQUEST;
        echoRequestMessage->hdr.icmp6_code = 0;
        echoRequestMessage->hdr.icmp6_dataun.icmp6_un_data16[SEQUENCE_NUMBER_UN_IDX] = 0;
        echoRequestMessage->data[PID_DATA_IDX] = getpid();
        echoRequestMessage->data[MAGIC_DATA_IDX] = MAGIC;
        *outMessageSize = sizeof(struct EchoPacketV6);
        if (outResponseSize != NULL) {
            *outResponseSize = sizeof(struct EchoPacketV6);
        }
    }
}

void updateChecksum(int version, void* buffer) {
    if (version == 4) {
        struct EchoPacketV4* echoRequestMessage = (struct EchoPacketV4*) buffer;
        echoRequestMessage->hdr.checksum = 0;
        echoRequestMessage->hdr.checksum = checksum((uint8_t*) echoRequestMessage, sizeof(*echoRequestMessage));
    } else {
        struct EchoPacketV6* echoRequestMessage = (struct EchoPacketV6*) buffer;
        echoRequestMessage->hdr.icmp6_cksum = 0;
        echoRequestMessage->hdr.icmp6_cksum = checksum((uint8_t*) echoRequestMessage, sizeof(*echoRequestMessage));
    }
}

void updateSequenceNumber(int version, uint16_t sequenceNumber, void* buffer) {
    if (version == 4) {
        struct EchoPacketV4* echoRequestMessage = (struct EchoPacketV4*) buffer;
        echoRequestMessage->hdr.un.echo.sequence = sequenceNumber;
    } else {
        struct EchoPacketV6* echoRequestMessage = (struct EchoPacketV6*) buffer;
        echoRequestMessage->hdr.icmp6_dataun.icmp6_un_data16[SEQUENCE_NUMBER_UN_IDX] = sequenceNumber;
    }
}

int main(int argc, char* argv[]) {
    if ((argc < 2) || (argc > 3)) {
        printf("Usage: %s [target] [-(4|6) version]\n", argv[0]);
        return 1;
    }

    // Parse command line options.
    char* target = argv[1];
    int version = 4;  // Default to using IPv4.
    int numPings = 4;
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

    // Create raw socket for sending and receiving ICMP messages.
    int sockId = 0;
    if (version == 4) {
        sockId = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); 
    } else {
        sockId = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    }
    if (sockId == -1) {
        printf("Error creating socket: %s\n", strerror(errno));
        return 1;
    }
    error = setsockopt(sockId, SOL_SOCKET, SO_RCVTIMEO, &TIMEOUT, sizeof(TIMEOUT));
    if (error < 0) {
        printf("Failed to set receive socket option correctly: %s\n", strerror(errno));
        return 1;
    }

    // Set up target address.
    struct sockaddr_storage addr;
    char* ipAddressString;
    error = buildSockaddr(version, target, &addr, &ipAddressString);
    if (error < 0) {
        return 1;
    }

    // Build message to send.
    uint8_t sendBuffer[SEND_BUFFER_SIZE];
    uint32_t messageSize = 0;
    uint32_t responseSize = 0;
    buildEchoMessage(version, sendBuffer, &messageSize, &responseSize);

    // Set up response fields.
    uint8_t recvBuffer[RECV_BUFFER_SIZE];
    struct sockaddr_storage returnAddr;
    uint32_t returnAddrSize = sizeof(returnAddr);

    printf("Pinging %s (%s):\n", ipAddressString, target);
    for (uint16_t sequenceNum = 0; sequenceNum < numPings; sequenceNum++) {
        // Reset structures for receiving data.
        struct timeval sendTime;
        struct timeval recvTime;
        memset(recvBuffer, 0, RECV_BUFFER_SIZE);

        // Update the sequence number in the message fields.
        updateSequenceNumber(version, sequenceNum, sendBuffer);

        // Calculate checksum.
        updateChecksum(version, sendBuffer);

        // Send echo request message.
        gettimeofday(&sendTime, NULL);
        int bytes = sendto(sockId, sendBuffer, messageSize, 0, (struct sockaddr*)(&addr), sizeof(addr));
        if (bytes < 0) {
            printf("Error sending message: %d (%s)\n", errno, strerror(errno));
            return 1;
        } else if (bytes != messageSize) {
            printf("Error: Did not send the expected number of bytes. Expected %u, sent %d.\n", messageSize, bytes);
            return 1;
        }

        // Continuously attempt to receive echo reply message until we either receive the expected echo response or time out.
        while (true) {
            errno = 0;  // Reset flag because it may have been set by a previous timeout.
            bytes = recvfrom(sockId, recvBuffer, RECV_BUFFER_SIZE, 0, (struct sockaddr*)(&returnAddr), &returnAddrSize);
            gettimeofday(&recvTime, NULL);
            if ((bytes < 0) && (errno != EAGAIN)) {
                printf("Error receiving message %d: (%s)\n", sequenceNum, strerror(errno));
                return 1;
            } else if (errno == EAGAIN) {
                // Timed out.
                printf("* * *\n");
                break;
            }

            if ((bytes >= responseSize) && verifyResponse(version, recvBuffer, sequenceNum, &addr, &returnAddr))
            {
                // Reply message was valid: print output to console.
                uint64_t latency = totalMicroseconds(recvTime) - totalMicroseconds(sendTime);
                printf("Reply %d from %s received in %ld.%ldms\n", 
                        sequenceNum, ipAddressString, latency / 1000, latency % 1000
                );
                break;
            }
            // else, message was not valid, so try again.
        }

        // Sleep for a second so that we don't spam both the console and the target server.
        sleep(1);
    }

    return 0;
}
