/*
 * Rule: INT30-C
 * Source: testcases
 * Status: FAIL - Should trigger INT30-C violation
 */

/*
 * Rule: INT30-C - Ensure that unsigned integer operations do not wrap
 * Status: FAIL
 * Reason: Network packet size calculation without wrap check
 */

#include <stdlib.h>
#include <stdint.h>

void allocate_packet(uint32_t num_packets, uint32_t packet_size) {
    // Multiplication may wrap - network vulnerability
    size_t total_size = num_packets * packet_size;  // Line 11 - VIOLATION

    void *buffer = malloc(total_size);
    if (buffer) {
        free(buffer);
    }
}

int main(void) {
    allocate_packet(1000000, 10000);  // Will wrap
    return 0;
}
