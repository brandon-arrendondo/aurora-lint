/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: FAIL - a macro that pastes only its parameters cannot spell the static's name
 */
#define CAT(a, b) a##b

static int alpha(void) /* Expect: here */
{
    return 1;
}

static int zeta_b(void) /* Expect: here */
{
    return 2;
}

int api(void)
{
    return CAT(1, 2);
}
