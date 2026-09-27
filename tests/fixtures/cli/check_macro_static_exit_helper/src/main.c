#include <stdio.h>
#include <stdlib.h>
#include "config.h"

static void die(const char *m) {
    fputs(m, stderr);
    exit(1);
}

#define REQUIRE(x) do { if (!(x)) die("req"); } while (0)

void f(void) {
    char *p = malloc(BUF_LEN);
    REQUIRE(p);
    p[0] = 1;
    free(p);
}
