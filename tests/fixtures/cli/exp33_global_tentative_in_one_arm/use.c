#include <stdio.h>

extern int globalOn;

void report(void) {
    int x;
    if (!globalOn) {
        printf("%d\n", x);
    }
}
