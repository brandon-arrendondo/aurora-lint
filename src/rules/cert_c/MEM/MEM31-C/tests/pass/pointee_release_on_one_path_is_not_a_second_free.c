/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: `drop_on_error` frees `*pp` only when told to, and reports
 * whether it did; the caller stops once it has. The second call through the
 * same `&p` is not a double free the analyzer can show: accusing one needs a
 * release of the pointee the callee's body always performs.
 */
#include <stdlib.h>

int drop_on_error(char **pp, int err)
{
    if (err) {
        free(*pp);
        return -1;
    }
    return 0;
}

void use(char *p, int err)
{
    if (drop_on_error(&p, err) < 0) {
        return;
    }
    drop_on_error(&p, 0);
}
