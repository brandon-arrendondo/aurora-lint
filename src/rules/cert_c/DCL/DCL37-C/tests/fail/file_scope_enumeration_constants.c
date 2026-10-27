/*
 * Rule: DCL37-C
 * Status: FAIL - an enumeration constant is an ordinary identifier, so at file
 * scope a leading underscore reserves it, and `_G` is reserved for any use.
 * Expect: count=2
 */

enum colour { _red, _Green, blue }; /* Expect: here */
