/*
 * Rule: DCL37-C
 * Status: FAIL - a typedef name is an ordinary identifier, so at file scope a
 * leading underscore reserves it, and `_T` is reserved for any use.
 * Expect: count=2
 */

typedef unsigned long _word, *_Word_ptr; /* Expect: here */
