/*
 * Rule: DCL37-C
 * Status: FAIL - names reserved for any use, declared at file scope, are
 * reported once each as reserved identifiers, not again as file-scope names
 * starting with an underscore.
 * Expect: count=2
 */

int _Limit; /* Expect: here */
static int __count; /* Expect: here */
