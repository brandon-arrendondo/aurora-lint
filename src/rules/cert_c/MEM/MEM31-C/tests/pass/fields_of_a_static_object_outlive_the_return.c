/*
 * Rule: MEM31-C
 * Source: real-world (pureftpd: a lookup fills a `static struct passwd`
 *         and returns its address)
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: `pwret` has static storage duration, so the blocks its
 * fields hold stay reachable after every return, as a `static char *` does.
 * Neither the early return nor `return &pwret` loses them.
 */
#include <stdlib.h>
#include <string.h>

struct passwd {
    char *pw_name;
    char *pw_passwd;
    char *pw_dir;
};

struct passwd *lookup(const char *a, const char *b)
{
    static struct passwd pwret;

    if ((pwret.pw_passwd = strdup(a)) == NULL)
        return NULL;
    if ((pwret.pw_dir = strdup(b)) == NULL)
        return NULL;
    return &pwret;
}
