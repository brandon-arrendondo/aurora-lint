/*
 * Description: a callee that casts its opaque handle into a local and
 * null-checks that local before using it validates the handle
 *
 * The opaque-handle wrapper: the public entry point forwards its handle to a
 * helper that casts it to the real type, returns early when it is null, and
 * only then reads through it.
 */
typedef struct handle handle;
struct impl {
    int rc;
};

static int impl_rc(handle *h)
{
    struct impl *p = (struct impl *)h;
    if (p == 0) {
        return 0;
    }
    return p->rc;
}

int handle_rc(handle *h)
{
    return impl_rc(h);
}
