/*
 * Rule: FIO50-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO50-C violation
 *
 * In C, << and >> are shifts, not stream insertion/extraction. An integer
 * shifted both ways, or a byte array unpacked with shifts, is not a file
 * stream.
 */

#include <stdint.h>
#include <stddef.h>

uint64_t crc64_update(uint64_t crc, const unsigned char *p, size_t n) {
    while (n--) {
        crc = (crc >> 8) ^ (uint64_t)(*p++);
        crc = (crc << 1) | (crc >> 63);
    }
    return crc;
}

void expand_key(const unsigned char *key_56, char *key) {
    key[0] = (char)key_56[0];
    key[1] = (char)(((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1));
    key[2] = (char)(((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2));
}
