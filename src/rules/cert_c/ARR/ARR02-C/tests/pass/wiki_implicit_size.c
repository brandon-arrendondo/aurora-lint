/*
 * Rule: ARR02-C
 * Source: wiki
 * Status: PASS - Should NOT trigger ARR02-C violation (brace initializer determines the bound; well-defined per C11 6.7.9p22, task 567)
 */

int a[] = {1, 2, 3, 4};