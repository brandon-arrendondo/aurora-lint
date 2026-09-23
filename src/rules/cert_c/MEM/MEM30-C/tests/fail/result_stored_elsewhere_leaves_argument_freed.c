/*
 * Rule: MEM30-C
 * Source: real-world (companion to pass/result_stored_back_into_freed_argument.c)
 * Status: FAIL - Should trigger MEM30-C violation
 * Reason: Clearing a freed argument's state when the call's result is
 *         stored back into it must not reach an argument the result is NOT
 *         stored into: `y = f(x)` leaves x freed, and a later read of x is
 *         a use-after-free. Likewise the second argument of a two-input
 *         consumer when only the first is overwritten.
 */

#include <stdlib.h>
#include <string.h>

struct wpabuf { size_t size; size_t used; void *buf; };

static void wpabuf_free(struct wpabuf *b)
{
    if (b) { free(b->buf); free(b); }
}

static struct wpabuf *wpabuf_alloc(size_t len)
{
    struct wpabuf *b = malloc(sizeof(*b));
    if (b) { b->buf = malloc(len); b->size = len; b->used = 0; }
    return b;
}

struct wpabuf *wpabuf_zeropad(struct wpabuf *buf, size_t len)
{
    struct wpabuf *msg = wpabuf_alloc(len);
    if (msg && buf)
        memcpy((char *)msg->buf + (len - buf->used), buf->buf, buf->used);
    wpabuf_free(buf);
    return msg;
}

struct wpabuf *wpabuf_concat(struct wpabuf *a, struct wpabuf *b)
{
    struct wpabuf *n = wpabuf_alloc(a->used + b->used);
    wpabuf_free(a);
    wpabuf_free(b);
    return n;
}

int result_elsewhere(struct wpabuf *x)
{
    struct wpabuf *y = wpabuf_zeropad(x, 32);
    if (!y)
        return -1;
    return (int)x->used + (int)y->used;   /* VIOLATION: x was freed by the callee */
}

int second_input_still_freed(struct wpabuf *a, struct wpabuf *b)
{
    a = wpabuf_concat(a, b);
    if (!a)
        return -1;
    wpabuf_free(b);                       /* VIOLATION: b was freed by the callee */
    wpabuf_free(a);
    return 0;
}
