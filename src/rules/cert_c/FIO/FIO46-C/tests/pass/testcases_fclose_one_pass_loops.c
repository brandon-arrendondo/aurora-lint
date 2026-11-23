/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - a do/while(0) block and a for loop bounded to one pass close the stream once
 */
#include <stdio.h>

void do_while_zero(FILE *s) {
    do {
        fclose(s);
    } while (0);
}

void counted_once(FILE *s) {
    int i;
    for (i = 0; i < 1; i++) {
        fprintf(s, "once\n");
        fclose(s);
    }
}
