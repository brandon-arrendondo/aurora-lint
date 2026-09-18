/*
 * Rule: MEM30-C
 * Source: task 1234
 * Status: FAIL - Should trigger MEM30-C violation.
 *
 * The companion to the PASS fixture. `&host` is passed to a function whose
 * own body writes nothing through it, so the variable still holds the
 * dangling pointer afterwards and dereferencing it is a genuine
 * use-after-free. The freed state is cleared at an address-of argument only
 * when the callee MIGHT write the parameter; a FunctionSummary that says it
 * never does is the one case where the pointer provably stays dangling.
 */

#include <stdlib.h>

static int count_hosts(char **hostp)
{
    return hostp ? 1 : 0;   /* reads the address, never writes *hostp */
}

int reconnect(char *host)
{
    free(host);
    if (count_hosts(&host) == 0) {
        return -1;
    }

    return host[0];         /* use-after-free: host was never reassigned */
}
