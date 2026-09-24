/*
 * Description: a null check on a cast alias that comes after the alias is
 * already dereferenced does not validate the handle
 *
 * The helper reads through the cast alias first and tests it for null only
 * afterwards, so a null handle is dereferenced before the check can help.
 */
typedef struct handle handle;
struct impl {
    int rc;
};

static int impl_rc(handle *h)
{
    struct impl *p = (struct impl *)h;
    int rc = p->rc;
    if (p == 0) {
        return 0;
    }
    return rc;
}

int handle_rc(handle *h)
{
    return impl_rc(h);
}
