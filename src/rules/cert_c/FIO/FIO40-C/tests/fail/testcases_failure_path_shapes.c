/*
 * Rule: FIO40-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO40-C violation
 *
 * Each function reads the array on a path where fgets() returned NULL,
 * before anything writes it: after a while loop that ends on failure, in
 * the else branch of a success test, after a stored result is tested, and
 * after a reset of a different array whose name merely starts the same.
 */

#include <stdio.h>
#include <string.h>

void after_loop(FILE *fp) {
    char line[128];
    while (fgets(line, sizeof line, fp) != NULL) {
        fputs(line, stdout);
    }
    printf("last: %s\n", line);
}

void else_branch(FILE *fp) {
    char buf[64];
    if (fgets(buf, sizeof(buf), fp)) {
        puts("read ok");
    } else {
        fprintf(stderr, "failed: %s\n", buf);
    }
}

void stored_then_tested(FILE *fp) {
    char buf[64];
    char *p = fgets(buf, sizeof(buf), fp);
    if (p == NULL) {
        perror("fgets");
    }
    puts(buf);
}

void other_array_reset(FILE *fp) {
    char b[32];
    char bb[32];
    if (fgets(b, sizeof(b), fp) == NULL) {
        bb[0] = '\0';
    }
    printf("%zu\n", strlen(b));
}

struct reader {
    char line[80];
};

void member_buffer(struct reader *r, FILE *fp) {
    if (!fgets(r->line, sizeof(r->line), fp)) {
        fputs("eof\n", stderr);
    }
    fputs(r->line, stdout);
}
