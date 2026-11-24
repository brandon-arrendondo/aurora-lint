/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: PASS - a static whose address escapes may be called through the pointer
 */
typedef void (*handler_t)(int);

static void on_open(int v)
{
    (void)v;
}

static void on_close(int v)
{
    (void)v;
}

static const handler_t handlers[] = { on_open };

handler_t pick(void)
{
    handler_t h = on_close;
    return handlers[0] ? handlers[0] : h;
}
