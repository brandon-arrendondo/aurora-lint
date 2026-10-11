/*
 * Rule: STR11-C
 * Source: testcases
 * Status: FAIL - Should trigger STR11-C violation
 *
 * EX1 allows an exact fit for an array that is deliberately not a string,
 * but only intent a compiler can check counts: a comment does not.
 */
/* Not a string: a fixed three-byte magic number. */
static const char magic[3] = "MZP";
