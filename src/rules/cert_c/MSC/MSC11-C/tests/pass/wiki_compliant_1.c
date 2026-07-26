/*
 * Rule: MSC11-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

assert(size <= SIZE_MAX/sizeof(char *));
table_size = size * sizeof(char *);