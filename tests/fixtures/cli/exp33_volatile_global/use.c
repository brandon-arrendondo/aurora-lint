#include <stdio.h>

extern volatile int globalFalse;

void report(void) {
    int x;
    if (globalFalse) {
        printf("%d\n", x);
    }
}
