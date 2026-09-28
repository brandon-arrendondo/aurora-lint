#include <stdio.h>
#include "flag.h"

void set_flag(void) {
    flag = 1;
}

void report(void) {
    int x;
    if (flag) {
        printf("%d\n", x);
    }
}
