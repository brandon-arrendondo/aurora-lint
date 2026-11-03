/*
 * Rule: ARR02-C
 * Source: custom
 * Status: PASS - Should NOT trigger ARR02-C violation
 * Description: Each arm of the #ifdef gives the array exactly its two
 * declared elements. The parser keeps both arms' entries so each one is
 * read, but the list it then holds (four entries) is no build's list, so
 * the count against the declared size is not read from it.
 */

int first(void)
{
    int t[2] = {
#ifdef WITH_HIGH_VALUES
        1, 2,
#else
        3, 4,
#endif
    };
    return t[0];
}
