/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: C orders a pointer against 0 without a cast, but a pointer
 * is never below 0, so `b < 0` does not test whether the allocation
 * failed. That reading belongs to an int result such as a descriptor. The
 * block is still held when this branch returns, so the return leaks it.
 */

#include <stdlib.h>

int fill(char *buf, size_t len);

int checked_fill(void)
{
    char *b = malloc(8);
    if (b < 0) {
        return -1; /* Expect: here */
    }
    if (b == NULL) {
        return -1;
    }
    fill(b, 8);
    free(b);
    return 0;
}
