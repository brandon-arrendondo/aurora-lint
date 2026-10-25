/*
 * Rule: MSC17-C
 * Source: synthetic, following MSC37-C's reading of C23 unreachable() (C23 7.21.1)
 * Status: PASS - C23 unreachable() ends a case section once the edition is declared
 * Settings: c_standard=c23
 */

#include <stddef.h>

int classify(int op)
{
    int r = 0;
    switch (op) {
    case 1:
        r = 10;
        break;
    case 2:
        r = 20;
        unreachable();
    case 3:
        r = 30;
        break;
    }
    return r;
}
