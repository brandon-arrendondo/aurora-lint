/*
 * Rule: ARR39-C
 * Source: testcases
 * Status: PASS - Should not trigger ARR39-C violation
 *
 * A count multiplied by sizeof(char) is multiplied by 1, so adding it to a
 * pointer that steps by one byte scales it once: there is no double scaling
 * to report, on a char buffer, a pointer to void, or a pointer whose element
 * type the file does not show. On a pointer to int the same offset is a
 * byte count added to elements, which fail/sizeof_dividend_still_scales.c
 * reports.
 */

#include <string.h>
#include <stddef.h>

void strlen_scaled(void) {
    char message[100] = "Hello";
    char *append_pos;

    append_pos = message + (strlen(message) * sizeof(char));
    strcpy(append_pos, " World");
}

void *void_scaled(void *buf, size_t n) {
    return buf + n * sizeof(char);
}

typedef struct opaque opaque_t;

opaque_t *unknown_scaled(opaque_t *p, size_t n) {
    return p + n * sizeof(char);
}
