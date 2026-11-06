/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - Each preprocessor arm sizes the array's typedef with its own index
 *
 * The array is declared outside the arms, but its typedef is defined in
 * them: eight elements with index 7 in one, four with index 3 in the
 * other. Each build pairs its index with its own size, so no build
 * indexes past the end.
 */

#if defined(A)
typedef int T[8];
#else
typedef int T[4];
#endif

int element(void)
{
    T buf;
#if defined(A)
    int i = 7;
#else
    int i = 3;
#endif
    buf[0] = 0;
    return buf[i];
}
