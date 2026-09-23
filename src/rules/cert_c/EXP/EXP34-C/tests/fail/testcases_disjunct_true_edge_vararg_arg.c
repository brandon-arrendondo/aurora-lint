/*
 * Rule: EXP34-C
 * Source: testcases (hostap src/crypto/crypto_openssl.c omac1_aes_vector,
 *         an earlier fix)
 * Status: FAIL - `cipher` is NULL unless one arm of the length if-chain
 *         assigned it, and the TRUE edge of `!ctx || !cipher || ...` is
 *         reached whether or not `!cipher` was the disjunct that made it
 *         true; the failure-path log passes the possibly-NULL `cipher` to
 *         a variadic wrapper's `%s`.
 *
 * Before 75162e1b this edge was misread as "every disjunct holds", which
 * reported `cipher` as DEFINITELY null -- correct verdict here, but the
 * same misread that turned `!p || !q` into "both null". The sound reading
 * is PossiblyNull, and a PossiblyNull argument to a project function was
 * not reported until d8de257a; between those two commits this finding was
 * lost. Sibling of testcases_conjunct_false_edge_vararg_arg.c: that one is
 * the `&&` FALSE edge, this one the `||` TRUE edge.
 */

#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>

struct mac_ctx {
    int state;
};

static void log_msg(int level, const char *fmt, ...)
{
    va_list ap;
    (void)level;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

static struct mac_ctx *mac_new(void);
static int mac_init(struct mac_ctx *ctx, const char *cipher);

int mac_vector(size_t key_len)
{
    struct mac_ctx *ctx = NULL;
    const char *cipher = NULL;

    if (key_len == 32)
        cipher = "aes-256-cbc";
    else if (key_len == 24)
        cipher = "aes-192-cbc";
    else if (key_len == 16)
        cipher = "aes-128-cbc";

    if (!(ctx = mac_new()) || !cipher || mac_init(ctx, cipher) != 1) {
        log_msg(1, "mac_init(cipher=%s) failed", cipher);
        return -1;
    }
    return 0;
}
