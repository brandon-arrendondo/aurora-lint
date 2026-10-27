/*
 * Rule: DCL37-C
 * Status: FAIL - each declarator of a file-scope declaration declares its own
 * identifier, so every reserved name in the list is reported, not only the
 * first.
 * Expect: count=4
 */

int _first, _Second, *_third, _fourth[4]; /* Expect: here */
