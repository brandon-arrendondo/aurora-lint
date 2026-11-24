/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - case 1 enters the loop with k at -5, so the body runs six times
 */
#include <stdio.h>

void f(FILE *fp, int x) {
    int k = -5;
    switch (x) {
    case 0:
        for (k = 0; k < 1; k++) {
        case 1:
            fclose(fp);
        }
    }
}
