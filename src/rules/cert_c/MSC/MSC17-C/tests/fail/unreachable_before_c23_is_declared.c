/*
 * Rule: MSC17-C
 * Source: synthetic, following MSC37-C's reading of C23 unreachable() (C23 7.21.1)
 * Status: FAIL - unreachable() is C23: with no edition declared the call proves nothing
 */

#include <stddef.h>

int classify(int op)
{
    int r = 0;
    switch (op) {
    case 1:
        r = 10;
        unreachable();
    case 2:
        r = 20;
        break;
    }
    return r;
}
