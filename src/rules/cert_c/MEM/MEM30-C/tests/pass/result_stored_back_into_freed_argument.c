/*
 * Rule: MEM30-C
 * Source: real-world (hostap's wpabuf_zeropad / wpabuf_concat / asn1_encaps
 *         call sites, ~52 adjudicated FPs in run 267)
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Reason: `x = f(x)` where f consumes its argument (frees it) and returns a
 *         fresh buffer or NULL. The callee's free was credited to x, and the
 *         store of f's result into x -- which follows the call -- never
 *         cleared it: the assignment visit runs before the right-hand side
 *         it walks into, so the free landed after the clear. Every later
 *         null-check, use and single free of x was then reported against a
 *         value x no longer holds. Same for a field target
 *         (`p->secret = f(p->secret)`) and a callee that frees two arguments
 *         and returns the rebuilt one.
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

/* consume-and-rebuild: frees its input, returns a fresh buffer or NULL */
struct wpabuf *wpabuf_zeropad(struct wpabuf *buf, size_t len)
{
    struct wpabuf *msg = wpabuf_alloc(len);
    if (msg && buf)
        memcpy((char *)msg->buf + (len - buf->used), buf->buf, buf->used);
    wpabuf_free(buf);
    return msg;
}

/* frees BOTH inputs, returns the concatenation or NULL */
struct wpabuf *wpabuf_concat(struct wpabuf *a, struct wpabuf *b)
{
    struct wpabuf *n = wpabuf_alloc(a->used + b->used);
    wpabuf_free(a);
    wpabuf_free(b);
    return n;
}

struct pfs { struct wpabuf *secret; };

int pad_then_free(struct wpabuf *x)
{
    x = wpabuf_zeropad(x, 32);
    if (x == NULL)
        return -1;
    if (x->used > 10) {
        wpabuf_free(x);     /* one free on this path */
        return 0;
    }
    wpabuf_free(x);         /* one free on the other */
    return 1;
}

int pad_field(struct pfs *p)
{
    p->secret = wpabuf_zeropad(p->secret, 32);
    if (p->secret == NULL)
        return -1;
    return (int)p->secret->used;
}

int concat_then_free(struct wpabuf *a, struct wpabuf *b)
{
    a = (struct wpabuf *)wpabuf_concat(a, b);
    if (!a)
        return -1;
    wpabuf_free(a);
    return 0;
}
