#include <stdio.h>

/* Non-static, so another translation unit may interpose it. */
int localReturnsFalse(void) {
    return 0;
}

void report(void) {
    int x;
    if (localReturnsFalse()) {
        printf("%d\n", x);
    }
}
