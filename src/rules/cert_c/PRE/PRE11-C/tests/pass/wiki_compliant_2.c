/*
 * Rule: PRE11-C
 * Source: wiki
 * Status: PASS - Should NOT trigger PRE11-C violation
 */

#define INCREMOD(x, max) ((x) = ((x) + 1) % (max))
