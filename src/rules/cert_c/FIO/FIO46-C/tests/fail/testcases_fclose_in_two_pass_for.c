/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - the body steps the counter back, so the loop runs again and closes the stream twice
 */
#include <stdio.h>

void f(FILE *s) {
    int i;
    for (i = 0; i < 1; i++) {
        fclose(s);
        i--;
    }
}
