/*
 * Rule: STR11-C
 * Source: custom
 * Status: PASS - Should NOT trigger STR11-C violation
 * Description: Each arm of the #ifdef initializes the array with one braced
 * literal that fits its bound. The arms have no comma between them, so they
 * are alternatives for one entry and are not read as the single longer
 * literal "ab" "cd" that no build has.
 */

char tag[4] = {
#ifdef WITH_LONG_TAGS
    "ab"
#else
    "cd"
#endif
};
