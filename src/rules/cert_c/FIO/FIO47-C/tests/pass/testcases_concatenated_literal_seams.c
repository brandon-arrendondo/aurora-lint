/*
 * Rule: FIO47-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO47-C violation
 *
 * A format string written as adjacent string literals is one literal after
 * translation phase 6, so a '%' at the end of one piece is not a conversion
 * followed by '"'. Where a <inttypes.h> macro sits between the pieces, its
 * expansion carries the conversion itself and the visible text alone cannot
 * be validated, so nothing is reported (ADR-0005: a finding must name a
 * construct that is actually there).
 */
#include <stdio.h>
#include <inttypes.h>

void print_pair(uint16_t addr, uint16_t len) {
    printf("0x%04" PRIX16 "  /  %" PRIu16 "\n", addr, len);
}

void print_wide(int32_t v) {
    printf("%" PRId32 "\n", v);
}

void print_joined(int n) {
    printf("count: %" "d\n", n);
}
