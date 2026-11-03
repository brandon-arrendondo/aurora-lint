/*
 * Rule: MSC37-C
 * Source: custom
 * Status: PASS - Should NOT trigger MSC37-C violation
 * Description: Each function returns a value, after a local array whose
 * initializer list holds conditional entries: single-arm guards, and an
 * #ifdef/#else whose arms are alternative entries. Unrepaired, the grammar
 * read the first #if as a block that swallowed the rest of the body, and
 * the `return` was not found in the function.
 */

#define PAIR(a, b) (((a) << 8) | (b))

unsigned short first_alg(void)
{
    const unsigned short algs[] = {
#if defined(WITH_ECDSA)
        PAIR(3,
             2),
#endif
#if defined(WITH_RSA)
        PAIR(1,
             2),
#endif
        0
    };
    return algs[0];
}

int first_size(void)
{
    const int sizes[] = {
#ifdef WITH_LARGE_SIZES
        4096, 8192,
#else
        512,
#endif
        0
    };
    return sizes[0];
}
