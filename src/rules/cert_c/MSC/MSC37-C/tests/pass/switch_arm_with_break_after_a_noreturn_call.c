/*
 * Rule: MSC37-C
 * Source: synthetic
 * Status: PASS - a break after a call that does not return, or after a block that ends in return, is never reached
 */

#include <stdlib.h>

int by_abort(int kind) {
    switch (kind) {
    case 1:
        return 1;
    default:
        abort();
        break;
    }
}

int by_block(int kind) {
    switch (kind) {
    case 1: {
        if (kind > 5) {
            return 2;
        }
        return 3;
    }
    default: {
        exit(1);
    }
    }
}
