/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO46-C violation
 * Description: File handle closed twice without reopening
 */

#include <stdio.h>

void double_close(void) {
    FILE *fp = fopen("data.txt", "r");
    if (fp == NULL) return;

    fclose(fp);
    fclose(fp);  /* Violation: double close */
}
