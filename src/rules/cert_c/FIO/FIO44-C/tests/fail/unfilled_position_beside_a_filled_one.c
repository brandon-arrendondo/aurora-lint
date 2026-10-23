/*
 * Rule: FIO44-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO44-C violation
 *
 * fgetpos() fills the pos of the first function only: the pos the second
 * function passes to fsetpos() was never obtained from fgetpos().
 */
#include <stdio.h>
#include <string.h>

int save(FILE *fp) {
    fpos_t pos;
    return fgetpos(fp, &pos);
}

int restore_zeroed(FILE *fp) {
    fpos_t pos;
    memset(&pos, 0, sizeof(pos));
    return fsetpos(fp, &pos);
}
