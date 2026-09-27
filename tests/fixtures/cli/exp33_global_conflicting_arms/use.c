#include <stdio.h>

extern int globalFalse;

void report(void) {
    int x;
    if (globalFalse) {
        printf("%d\n", x);
    }
}
