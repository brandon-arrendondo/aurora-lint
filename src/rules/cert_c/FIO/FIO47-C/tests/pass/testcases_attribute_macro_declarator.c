/*
 * Rule: FIO47-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO47-C violation
 *
 * An integer declared through an attribute macro is still an integer.
 * Before parsing, the macro's spelling is replaced by a same-length comment
 * marker, so a check that reads the declaration's raw text finds a '*' in
 * it; the argument's type has to come from the declaration it resolves to
 * (ADR-0006), whose type and declarator carry no comment.
 */
#include <stdio.h>
#include <stdint.h>

#define UNUSED __attribute__((unused))

typedef unsigned long word_t;

void report(uint32_t status, word_t sp) {
    uint32_t UNUSED id = status & 0xff;
    word_t UNUSED stack = sp + 8;

    printf("ID: %d\n", id);
    printf("stack: 0x%lx\n", stack);
}
