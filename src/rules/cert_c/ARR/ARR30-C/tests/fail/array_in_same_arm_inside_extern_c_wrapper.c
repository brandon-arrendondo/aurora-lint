/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - An array indexed past its end in its own arm, inside an extern "C" wrapper
 * Expect: count=1
 *
 * The header's #ifdef __cplusplus wrapper puts the file in an extern "C"
 * block. Where A is defined, buf has 4 elements and buf[9] is past the end.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef A
int buf[4];
#endif

int get(void)
{
#ifdef A
    return buf[9];
#else
    return 0;
#endif
}

#ifdef __cplusplus
}
#endif
