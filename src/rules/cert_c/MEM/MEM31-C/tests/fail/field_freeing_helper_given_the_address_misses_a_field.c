/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: `freesome` frees only `p->pw_passwd`. Handed `&pw`, it
 * releases the caller's `pw.pw_passwd` and nothing else, so `pw.pw_dir`
 * still leaks at the label the last failure jumps to.
 * Expect: count=2
 */
#include <stdlib.h>
#include <string.h>

struct passwd {
    char *pw_name;
    char *pw_passwd;
    char *pw_dir;
};

static void freesome(struct passwd *const p)
{
    free(p->pw_passwd);
    p->pw_passwd = NULL;
}

int fill(const char *a, const char *b)
{
    struct passwd pw;

    if ((pw.pw_passwd = strdup(a)) == NULL)
        goto error;
    if ((pw.pw_dir = strdup(b)) == NULL)
        goto error;
    if (a[0] == '\0')
        goto error; /* Expect: here */
    freesome(&pw);
    free(pw.pw_dir);
    return 0;

error:
    freesome(&pw);
    return -1; /* Expect: here */
}
