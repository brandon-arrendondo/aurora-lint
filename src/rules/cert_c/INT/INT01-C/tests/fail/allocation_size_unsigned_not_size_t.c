/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: FAIL - an allocation size typed uint32_t
 *
 * length is unsigned, but uint32_t is not size_t: the size of the payload
 * is held in a type of its own width.
 */
#include <stdint.h>
#include <stdlib.h>

uint32_t read_u32(void);

void *copy_payload(void) {
    uint32_t length = read_u32();
    return malloc(length);
}
