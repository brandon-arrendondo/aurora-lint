/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM30-C violation
 */

/*
 * Rule: MEM30-C - Do not access freed memory
 * Status: PASS
 * Reason: `f(&p)` after `free(p)` passes the ADDRESS of the variable, not
 *         the freed pointer: it is the out-parameter idiom that refills the
 *         slot. Taking the address is neither a use nor a dereference of the
 *         freed pointer, and the freed state is cleared by default -- for a
 *         callee whose summary writes the parameter on every path and for a
 *         callee with no summary alike (EXP33-C's `&var`-initializes policy,
 *         task 1065 bug #3). curl's lib/ftp.c `curlx_free(newhost); result =
 *         ftp_control_addr_dup(data, &newhost);` and the six uses that
 *         followed it (task 1234).
 */

#include <stdlib.h>
#include <string.h>

/* writes *out on every returning path */
int addr_dup(int flag, char **out)
{
    if (flag)
        *out = strdup("a");
    else
        *out = NULL;
    return *out ? 0 : -1;
}

int refill(int flag)
{
    char *h = strdup("x");
    free(h);
    if (addr_dup(flag, &h))
        return -1;
    return (int)strlen(h);
}

/* no summary at all: default credit, as EXP33-C gives an unknown callee */
void unknown_refill(char **out);

int unknown(void)
{
    char *h = strdup("x");
    free(h);
    unknown_refill(&h);
    return (int)strlen(h);
}

/* through a struct field */
struct conn { char *host; };

int field_refill(struct conn *c, int flag)
{
    free(c->host);
    if (addr_dup(flag, &c->host))
        return -1;
    return (int)strlen(c->host);
}
