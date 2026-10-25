/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: FAIL - an int added to sizeof as an allocation size
 *
 * The sum is a size_t by the usual conversions, but only one of its
 * operands is: extra, the size of the payload after the header, is held in
 * an int.
 */
#include <stdlib.h>

struct header { int kind; };

int payload_bytes(void);

void *make_message(void) {
    int extra = payload_bytes();
    return malloc(sizeof(struct header) + extra);
}
