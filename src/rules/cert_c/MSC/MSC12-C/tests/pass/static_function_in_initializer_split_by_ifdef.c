/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: PASS - the static is stored in an initializer whose entries differ by #ifdef arm
 */
struct methods {
    int (*open)(int);
    int (*held)(int);
};

static int do_open(int v)
{
    return v + 1;
}

#ifdef DEBUG_CHECKS
static int check_held(int v)
{
    return v != 0;
}
#endif

const struct methods *get_methods(void)
{
    static const struct methods m = {
        do_open,
#ifdef DEBUG_CHECKS
        check_held
#else
        0
#endif
    };
    return &m;
}
