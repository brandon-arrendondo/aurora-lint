/*
 * Rule: MEM30-C
 * Source: task 1234 (curl lib/ftp.c:2186-2234 'newhost', lib/ldap.c
 *         'unescaped', lib/sendf.c 'writer')
 * Status: PASS - Should NOT trigger MEM30-C violation.
 *
 * The out-parameter repair idiom: free the old pointer, then hand the
 * ADDRESS OF THE VARIABLE to a function that writes a fresh pointer back
 * through it. Two separate things used to go wrong here. Passing `&host`
 * was itself reported as "passing freed pointer to function" -- but `&host`
 * hands over the address of the variable, not the dangling value in it, and
 * `lvalue_of` unwraps `&p` and `*p` identically, which is what made one look
 * like the other. And nothing cleared the freed state at the call, so every
 * later use of the variable in the function was reported against the
 * original free.
 *
 * curl's `ftp_control_addr_dup` assigns `*newhostp` on every return path,
 * including the failure one; the sibling FAIL fixture covers a callee that
 * writes nothing.
 */

#include <stdlib.h>

extern char *dup_current_address(void);

static int refresh_host(char **hostp)
{
    *hostp = dup_current_address();
    return *hostp ? 0 : -1;
}

int reconnect(char *host)
{
    free(host);
    if (refresh_host(&host)) {   /* &host is not a use of the freed object */
        return -1;
    }

    if (host[0] == '\0') {       /* host was reassigned through the out-param */
        return -1;
    }

    free(host);                  /* not a double free: this frees the new one */
    return 0;
}
