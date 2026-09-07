/*
 * Rule: MSC13-C
 * Source: curl lib/urldata.h + lib/url.c, seL4 include/kernel/boot.h
 *         (task 966)
 * Status: FAIL - Should trigger MSC13-C violations
 *
 * The macro-hidden-use check asks whether an unexpanded macro body names a
 * caller-scope variable as a free identifier. Its token scan excluded only
 * the macro's own parameters, so it also matched identifiers that are not
 * variable references at all and cannot bind to a local of the same name:
 *
 *   - `proxy` after `.` names a struct member, not curl's
 *     `char *proxy = NULL;`
 *   - `pptr_t` inside `(pptr_t)` is the type of a cast, not an object.
 *
 * Both collisions silently suppressed a real finding, which is the
 * expensive direction of error: a false negative nothing downstream can
 * recover.
 */

struct bits_s { int proxy; };
struct conn { struct bits_s bits; };

typedef unsigned long pptr_t;

#define CONN_IS_PROXIED(x) ((x)->bits.proxy)
#define PPTR_OF(cap) ((pptr_t)cap_get_capPtr(cap))

extern unsigned long cap_get_capPtr(int cap);
extern void sink(int v);

void member_collision(struct conn *c) {
    char *proxy = 0;
    sink(CONN_IS_PROXIED(c));
}

void cast_type_collision(int cap) {
    unsigned long pptr_t = 0;
    sink((int)PPTR_OF(cap));
}
