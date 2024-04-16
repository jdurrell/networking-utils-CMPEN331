// Fix VSCode intellisense.
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "util.h"

// Calculate the 16-bit Internet checksum of the given byte array. RFC 1071.
// If passing a message directly to this function, ensure the checksum field is zeroed beforehand.
// arr must not be null.
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

// Returns whether the two given addresses are equal.
uint8_t ipv6AddressesAreEqual(struct in6_addr a, struct in6_addr b) {
    for (int i = 0; i < 4; i++) {
        if (a.__in6_u.__u6_addr32[i] != b.__in6_u.__u6_addr32[i]) {
            return false;
        }
    }
    return true;
}

// Resolves the string given by host to an ip address struct for the given IP version.
// The user can supply 0 to version to not specify an address family.
// Returns a null pointer if an error occurred, or if no addresses were found.
struct addrinfo* resolveHostnameOrIP(char* host, int version) {
    if (host == NULL) {
        printf("Cannot resolve hostname because the given input is null.\n");
        return NULL;
    }
    
    // Resolve hostname to IP address.
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    if (version == 0) {
        hints.ai_family = 0;
        hints.ai_protocol = IPPROTO_ICMP;
    } else if (version == 4) {
        hints.ai_family = AF_INET;
        hints.ai_protocol = IPPROTO_ICMP;
    } else {
        hints.ai_family = AF_INET6;
        hints.ai_protocol = IPPROTO_ICMPV6;
    }
    hints.ai_flags = 0;
    hints.ai_socktype = SOCK_RAW;
    struct addrinfo* addrinfo = NULL;
    int error = getaddrinfo(host, NULL, &hints, &addrinfo);
    if (error < 0) {
        printf("Error resolving host %s: %d (%s)\n", host, error, strerror(error));
        return NULL;
    } else if (addrinfo == NULL) {
        printf("No addresses found for given host %s.\n", host);
        return NULL;
    }

    return addrinfo;
}

// Print the byte values of the given buffer one-by-one, up to len.
void debugPrintBufferBytes(uint8_t* buffer, int len) {
    for (int i = 0; i < len; i++) {
        printf("%u ", buffer[i]);
    }
    printf("\n");
}

// Returns the total number of microseconds indicated by 'time'.
uint64_t totalMicroseconds(struct timeval time) {
    return (((uint64_t)(time.tv_sec)) * 1000000) + (uint64_t)(time.tv_usec);
}

// Print the values of the given ICMP header.
void debugPrintICMPHeader(struct icmphdr hdr) {
    printf("Type: %d\n", hdr.type);
    printf("Code: %d\n", hdr.code);
    printf("Id: %d\n", ntohs(hdr.un.echo.id));
    printf("Sequence Number: %d\n", ntohs(hdr.un.echo.sequence));
    printf("Checksum: %u\n", hdr.checksum);
}

// Print the values of the given IPv4 header.
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
    printf("saddr: %u.%u.%u.%u\n", buf[3], buf[2], buf[1], buf[0]);
    memcpy(buf, &(iphdr.daddr), 4);
    printf("daddr: %u.%u.%u.%u\n", buf[3], buf[2], buf[1], buf[0]);
}
