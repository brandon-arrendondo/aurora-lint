/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: C11 7.21.7.8 lets putc evaluate only its stream argument more than
 * once; the character argument is evaluated exactly once (7.1.4).
 */

#include <stdio.h>

void r(FILE *fp, const char *buf) {
    int i = 0;
    putc(buf[i++], fp);
}
