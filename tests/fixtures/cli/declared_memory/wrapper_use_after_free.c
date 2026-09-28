/* The wrapper's body hands its parameter to the declared hook, so its
 * summary proves it frees that parameter. */
#include <stdlib.h>

static void my_release(char *q) { platform_give_back(q); }

void use_after_release(void) {
    char *p = malloc(8);
    if (p == NULL) return;
    my_release(p);
    p[0] = 1;
}
