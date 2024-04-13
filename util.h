// Header guard.
#ifndef UTIL_INCLUDE
#define UTIL_INCLUDE 1

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <stdint.h>
#include <sys/time.h>

void debugPrintBufferBytes(uint8_t* buffer, int len);
void debugPrintICMPInfo(struct icmphdr hdr);
uint64_t totalMicroseconds(struct timeval time);
uint16_t checksum(uint8_t* arr, int len);

#endif