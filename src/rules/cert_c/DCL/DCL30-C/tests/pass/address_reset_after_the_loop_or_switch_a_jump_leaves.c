/*
 * Rule: DCL30-C
 * Status: PASS - Should NOT trigger DCL30-C violation
 * Reason: A break or continue whose loop or switch holds the store lands
 *         at that statement's end or its next iteration, so a reset after
 *         the statement still runs on that path. A reset in the same
 *         preprocessor arm as the store runs whenever the store does. A
 *         pointer parameter retargeted to a local no longer reaches the
 *         caller's storage.
 */

int *g;

int check(void);
void use(void);

void do_while_zero(void)
{
    int x = 0;
    do {
        g = &x;
        if (check())
            break;
        check();
    } while (0);
    g = 0;
}

void forever(void)
{
    int x = 0;
    for (;;) {
        g = &x;
        if (check())
            break;
    }
    g = 0;
}

void countdown(int n)
{
    int x = 0;
    while (n--) {
        g = &x;
        if (check())
            continue;
        use();
    }
    g = 0;
}

void one_case(int k)
{
    int x = 0;
    switch (k) {
    case 1:
        g = &x;
        break;
    }
    g = 0;
}

void feature(void)
{
    int x = 0;
#ifdef FEATURE
    g = &x;
    use();
    g = 0;
#endif
    use();
}

void retargeted(int **out)
{
    int *tmp;
    int x = 0;
    out = &tmp;
    *out = &x;
}
