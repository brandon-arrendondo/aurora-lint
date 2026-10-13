/*
 * Rule: POS34-C
 * Source: synthetic
 * Status: PASS - a typedef local to another function does not give the file-scope typedef of that name an array member
 */

#include <stdlib.h>
#include <string.h>

void other(void) {
    typedef struct {
        char env[8];
    } S;
    S t;
    (void)t;
}

typedef struct {
    char *env;
} S;

int set(void) {
    S s;
    s.env = strdup("A=1");
    return putenv(s.env);
}
