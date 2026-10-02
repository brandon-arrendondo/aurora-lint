/*
 * Rule: EXP14-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * uint64_t is exactly 64 bits, but ISO C does not bound int above, so an
 * implementation may give int 64 bits or more (or fewer: the guarantee is
 * only that int is at least 16 bits wide). Without a declared data model
 * even a 64-bit exact-width type is not known to be at least as wide as int,
 * so its complement may be promoted and is reported. Declaring lp64 or llp64
 * fixes int at 32 bits and clears it.
 */

#include <stdint.h>

uint64_t invert(uint64_t value) {
    uint64_t result = ~value; /* VIOLATION */
    return result;
}
