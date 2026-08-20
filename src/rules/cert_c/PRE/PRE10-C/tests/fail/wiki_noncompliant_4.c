/*
 * Rule: PRE10-C
 * Source: wiki
 * Status: FAIL - Should trigger PRE10-C violation
 */

/*
 * Swaps two values and requires
 * tmp variable to be defined.
 */
#define SWAP(x, y) { tmp = (x); (x) = (y); (y) = tmp; }
