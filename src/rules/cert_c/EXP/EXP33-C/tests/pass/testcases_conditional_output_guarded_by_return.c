/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation. Same conditional-writing
 * callee as the FAIL fixture beside it, called the way curl's pop3, smtp and
 * imap call it: the returned mechanism bit is tested first, and short-circuit
 * evaluation means `llen` is only read where the write happened. A caller that
 * tests the result before reading the output is the caller the conditional
 * write was written for (task 1065 bug #3, tools_sqc).
 */
#include <stddef.h>

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
    unsigned short mechbit = decode_mech(word, wordlen, &llen);

    if (mechbit && llen == wordlen)
        *authmechs |= mechbit;
}
