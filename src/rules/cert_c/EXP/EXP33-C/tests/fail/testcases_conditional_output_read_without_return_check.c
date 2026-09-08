/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP33-C violation. `decode_mech` writes `*len`
 * only when a table entry matches and returns 0 otherwise, so its trailing
 * `return 0` is a path that leaves the caller's `llen` unwritten. This caller
 * stores the returned bit but never tests it before comparing `llen`, which is
 * curl's `openldap.c:730` (task 1065 bug #3, tools_sqc). The prescan summary
 * carries the callee as a proven conditional writer, which is what stops the
 * "assume `&var` initializes" default from crediting the write outright.
 */
#include <stddef.h>
#include <stdio.h>

struct mech {
    const char *name;
    size_t len;
    unsigned short bit;
};

static const struct mech mechtable[] = {
    { "PLAIN", 5, 1 },
    { "LOGIN", 5, 2 },
    { NULL, 0, 0 }
};

static unsigned short decode_mech(const char *ptr, size_t maxlen, size_t *len)
{
    unsigned int i;

    for (i = 0; mechtable[i].name; i++) {
        if (maxlen >= mechtable[i].len && ptr[0] == mechtable[i].name[0]) {
            *len = mechtable[i].len;
            return mechtable[i].bit;
        }
    }

    return 0;
}

void caller(const char *word, size_t wordlen, unsigned short *authmechs)
{
    size_t llen;
    unsigned short mech = decode_mech(word, wordlen, &llen);

    if (wordlen == llen)
        *authmechs |= mech;
}
