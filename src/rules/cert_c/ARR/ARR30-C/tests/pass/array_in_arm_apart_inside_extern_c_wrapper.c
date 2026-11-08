/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - An array of an arm apart, inside an extern "C" wrapper
 *
 * The header's #ifdef __cplusplus wrapper puts the file in an extern "C"
 * block. buf exists only where A is defined, and the access is in the arm
 * where A is not, so no buf of 4 is indexed there.
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
    return 0;
#else
    return buf[9];
#endif
}

#ifdef __cplusplus
}
#endif
