/*
 * Rule: FIO40-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO40-C violation
 *
 * No path from a failed fgets() reads the array before something writes
 * it: the success branch is the only reader, the failure branch leaves the
 * function or resets with memset or strcpy, the array is read again by
 * fgets, and sizeof does not read the array's contents.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int success_branch_only(FILE *fp) {
    char buf[64];
    if (fgets(buf, sizeof(buf), fp) != NULL) {
        puts(buf);
        return 1;
    }
    return 0;
}

void failure_returns(FILE *fp) {
    char buf[64];
    if (fgets(buf, sizeof(buf), fp) == NULL) {
        return;
    }
    puts(buf);
}

void failure_exits(FILE *fp) {
    char buf[64];
    if (!fgets(buf, sizeof(buf), fp)) {
        exit(EXIT_FAILURE);
    }
    puts(buf);
}

void memset_reset(FILE *fp) {
    char buf[64];
    if (fgets(buf, sizeof(buf), fp) == NULL) {
        memset(buf, 0, sizeof(buf));
    }
    puts(buf);
}

void strcpy_reset(FILE *fp) {
    char buf[64];
    if (fgets(buf, sizeof(buf), fp) == NULL) {
        strcpy(buf, "default");
    }
    puts(buf);
}

void read_again(FILE *fp, FILE *fallback) {
    char buf[64];
    if (fgets(buf, sizeof(buf), fp) == NULL) {
        if (fgets(buf, sizeof(buf), fallback) == NULL) {
            buf[0] = '\0';
        }
    }
    puts(buf);
}

size_t size_only(FILE *fp) {
    char buf[64];
    if (fgets(buf, sizeof(buf), fp) == NULL) {
        return sizeof(buf);
    }
    return strlen(buf);
}

void loop_without_later_use(FILE *fp) {
    char line[128];
    while (fgets(line, sizeof line, fp)) {
        fputs(line, stdout);
    }
}
