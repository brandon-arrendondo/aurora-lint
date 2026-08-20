/*
 * Rule: PRE05-C
 * Source: wiki
 * Status: PASS - Should NOT trigger PRE05-C violation
 */

#define JOIN(x, y) JOIN_AGAIN(x, y)
#define JOIN_AGAIN(x, y) x ## y
