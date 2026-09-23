/*
 * Rule: EXP34-C
 * Source: testcases
 * Status: PASS - `buf` is unguarded after malloc and so possibly NULL, but
 *         the vararg slot it lands in is a `%p`: printf writes the pointer
 *         VALUE and never reads the pointee, so there is no dereference to
 *         report at this call.
 *
 * Before the slot model every `...` argument was treated alike, so this
 * reported "Passing potentially null pointer 'buf' to 'log_msg' which does
 * not check for NULL" -- a dereference a reader of the line cannot find,
 * which is a misfire rather than a judgment FP (`docs/adr/0005`). The trailing
 * `%lu`s are not pointers either; only a conversion that reads or writes
 * through the pointer counts.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

struct wpabuf {
    size_t size;
    size_t used;
};

static void log_msg(int level, const char *fmt, ...)
{
    va_list ap;
    (void)level;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

void trace_overflow(size_t len)
{
    struct wpabuf *buf = malloc(sizeof(*buf));

    log_msg(1, "wpabuf %p overflow len=%lu", buf, (unsigned long)len);
}
