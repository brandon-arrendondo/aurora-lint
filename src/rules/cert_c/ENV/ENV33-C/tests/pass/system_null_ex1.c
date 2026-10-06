/*
 * Rule: ENV33-C
 * Source: regression
 * Status: PASS under both presets
 *
 * system(NULL), in any spelling of a null pointer constant, only asks whether
 * a command processor is available and invokes none (CERT ENV33-C-EX1). It is
 * not reported under either policy, even in a function that reads untrusted
 * input and takes a pointer, where the default policy's relaxation does not
 * apply.
 */

#include <stdio.h>
#include <stdlib.h>

int shell_available(const char *label)
{
    char buf[16];
    if (fgets(buf, sizeof buf, stdin) == NULL) {
        return 0;
    }
    if (system(NULL) == 0) {
        return 0;
    }
    if (system(0) == 0) {
        return 0;
    }
    return system((char *)0) != 0 && label != NULL;
}
