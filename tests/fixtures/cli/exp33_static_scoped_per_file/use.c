#include <stdio.h>

/* A different object that happens to share the name, and is written. */
static int flag = 0;

void set_flag(void) {
    flag = 1;
}

void report(void) {
    int x;
    if (flag) {
        printf("%d\n", x);
    }
}
