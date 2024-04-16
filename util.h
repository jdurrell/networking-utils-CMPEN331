// Header guard.
#ifndef UTIL_INCLUDE
#define UTIL_INCLUDE 1

// Fix VSCode intellisense.
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <netdb.h>
#include <stdint.h>
#include <sys/time.h>

uint16_t checksum(uint8_t* arr, int len);
uint8_t ipv6AddressesAreEqual(struct in6_addr a, struct in6_addr b);
struct addrinfo* resolveHostnameOrIP(char* host, int version);
uint64_t totalMicroseconds(struct timeval time);

// Debug tools.
void debugPrintBufferBytes(uint8_t* buffer, int len);
void debugPrintICMPHeader(struct icmphdr hdr);
void debugPrintIpHeader(struct iphdr iphdr);

#endif