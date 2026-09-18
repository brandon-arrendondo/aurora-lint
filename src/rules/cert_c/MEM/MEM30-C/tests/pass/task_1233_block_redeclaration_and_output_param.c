/*
 * Rule: MEM30-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Description: curl lib/ldap.c `_ldap_url_parse2` and lib/ftp.c. Three
 * things the scope-flat walker got wrong (task 1233): (1) a fresh
 * `char *unescaped;` in a later sibling block is a new binding and must
 * clear the freed state the previous block left behind -- the same rule
 * `T *p = ...;` already followed (task 232); (2) `f(&p)` passes the ADDRESS
 * of `p`, not the freed pointer in it, and refills `p` as an output
 * parameter; (3) `&p` is address-of, not a dereference.
 */

#include <stdlib.h>

int urldecode(const char *in, char **out);
char *to_tchar(const char *s);
int addr_dup(char **out);

int parse(const char *dn, const char *filter, char **dn_out, char **filter_out,
          char *newhost)
{
    int rc = 0;
    {
        char *unescaped;
        if(urldecode(dn, &unescaped))
            return -1;
        *dn_out = to_tchar(unescaped);
        free(unescaped);
    }
    {
        char *unescaped;                 /* fresh binding, not the freed one */
        if(urldecode(filter, &unescaped))
            return -1;
        *filter_out = to_tchar(unescaped);
        free(unescaped);
    }

    /* ftp.c: free, then refill through an output parameter. */
    free(newhost);
    rc = addr_dup(&newhost);
    if(rc)
        return rc;
    return newhost[0];
}
