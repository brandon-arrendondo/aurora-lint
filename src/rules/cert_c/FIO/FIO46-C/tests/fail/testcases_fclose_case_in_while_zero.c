/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - case 1 enters the while (0) body, closes, and the close after the switch closes again
 */
#include <stdio.h>

void f(FILE *fp, int x) {
    switch (x) {
    case 0:
        while (0) {
        case 1:
            fclose(fp);
        }
    }
    fclose(fp);
}
