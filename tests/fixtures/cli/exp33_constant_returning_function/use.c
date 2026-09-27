#include <stdio.h>

int globalReturnsFalse(void);

void report(void) {
    int x;
    if (globalReturnsFalse()) {
        printf("%d\n", x);
    }
}
