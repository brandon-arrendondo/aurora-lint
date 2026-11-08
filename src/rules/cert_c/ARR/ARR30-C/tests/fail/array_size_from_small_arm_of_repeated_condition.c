/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - The access is compiled only with the arm declaring four elements
 * Expect: count=1
 *
 * Both conditionals open on `#if A`. The last declaration has eight
 * elements, but the arm compiled with the access declares four.
 */

int element(void)
{
#if A
    int buf[4];
#else
    int buf[8];
#endif
#if A
    return buf[7];
#else
    return buf[0];
#endif
}
