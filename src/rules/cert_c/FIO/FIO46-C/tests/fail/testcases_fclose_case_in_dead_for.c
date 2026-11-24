/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - case 1 enters a for body its header never runs, and the close after it closes again
 */
#include <stdio.h>

void f(FILE *fp, int x) {
    int k = 0;
    switch (x) {
    case 0:
        for (k = 0; k < 0; k++) {
        case 1:
            fclose(fp);
        }
    }
    fclose(fp);
}
