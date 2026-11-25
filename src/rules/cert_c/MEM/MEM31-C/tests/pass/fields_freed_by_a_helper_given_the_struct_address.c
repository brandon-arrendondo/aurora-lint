/*
 * Rule: MEM31-C
 * Source: real-world (pureftpd: a lookup fills a `struct passwd` and its
 *         `error:` label releases the fields through a static helper
 *         handed `&pwret`)
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: `freefields` frees `p->pw_passwd`, `p->pw_dir` and
 * `p->pw_shell`. Handed `&pw`, its `p->f` is the caller's `pw.f`, so every
 * field is released on the success path and at the label the failures jump
 * to.
 */
#include <stdlib.h>
#include <string.h>

struct passwd {
    char *pw_name;
    char *pw_passwd;
    char *pw_dir;
    char *pw_shell;
};

static void freefields(struct passwd *const p)
{
    free(p->pw_passwd);
    p->pw_passwd = NULL;
    free(p->pw_dir);
    p->pw_dir = NULL;
    free(p->pw_shell);
    p->pw_shell = NULL;
}

int fill(const char *a, const char *b, const char *c)
{
    struct passwd pw;

    if ((pw.pw_passwd = strdup(a)) == NULL)
        goto error;
    if ((pw.pw_dir = strdup(b)) == NULL)
        goto error;
    if ((pw.pw_shell = strdup(c)) == NULL)
        goto error;
    freefields(&pw);
    return 0;

error:
    freefields(&pw);
    return -1;
}
