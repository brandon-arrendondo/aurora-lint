/*
 * Rule: MEM30-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Description: curl lib/ldap.c. FREE_ON_WINLDAP(x) is curlx_free(x) under
 * `#ifdef USE_WIN32_LDAP` and a no-op in the `#else`; the collector keeps the
 * first body (a build-config macro no platform profile settles), while the
 * walker also sees the non-Windows `attr = attribute` alias. The name
 * contains FREE, so the call was treated as freeing `attribute`, and the
 * genuine ldap_memfree(attribute) on the next line was reported as a
 * double-free -- on every one of the eight error branches. A macro with two
 * conflicting live definitions is opaque: its NAME is not evidence of a
 * free.
 */

#include <stdlib.h>

#ifdef USE_WIN32_LDAP
#define FREE_ON_WINLDAP(x) free(x)
#else
#define FREE_ON_WINLDAP(x) do {} while(0)
#endif

char *first_attribute(void);
char *next_attribute(void);
void ldap_memfree(void *p);
int client_write(const char *s, int n);

int write_attributes(void)
{
    char *attribute;
    int result = 0;

    for(attribute = first_attribute(); attribute; attribute = next_attribute()) {
#ifdef USE_WIN32_LDAP
        char *attr = convert(attribute);
#else
        char *attr = attribute;
#endif
        result = client_write("\t", 1);
        if(result) {
            FREE_ON_WINLDAP(attr);
            ldap_memfree(attribute);
            goto quit;
        }
        result = client_write(attr, 2);
        if(result) {
            FREE_ON_WINLDAP(attr);
            ldap_memfree(attribute);
            goto quit;
        }
        FREE_ON_WINLDAP(attr);
        ldap_memfree(attribute);
    }
quit:
    return result;
}
