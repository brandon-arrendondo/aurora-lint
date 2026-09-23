/*
 * Rule: INT32-C
 * Source: task 1276 (valkey src/hashtable.c:889
 *         `(1ul << (ENTRIES_PER_BUCKET << 3)) - 1ul`)
 * Status: PASS - Should NOT trigger INT32-C violation
 * Reason: `1ul` is an unsigned long literal, so the shift and the subtraction
 *         are unsigned arithmetic. Only a bare trailing `u`/`U` was
 *         recognized; with a length suffix too (`ul`, `UL`, `ull`) the literal
 *         read as "unknown" and the expression typed itself from the shift
 *         count's signed `3`.
 */

#include <stdint.h>

#define ENTRIES_PER_BUCKET 7

uint64_t valid_mask(uint64_t matches)
{
    const uint64_t valid_entry_mask = (1ul << (ENTRIES_PER_BUCKET << 3)) - 1ul;
    const uint64_t hex_mask = (0xful << 4) - 1UL;
    return matches & 0x8080808080808080ul & valid_entry_mask & hex_mask;
}
