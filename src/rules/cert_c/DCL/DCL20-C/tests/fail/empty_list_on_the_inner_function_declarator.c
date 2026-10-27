/*
 * Rule: DCL20-C
 * Source: aurora-lint
 * Status: FAIL - `get_handler()` is declared old-style
 * Expect: count=1
 *
 * The declarator of the outer function declarator is a function declarator
 * of its own: `get_handler` takes unspecified arguments and returns a pointer
 * to a function taking (void).
 */

int (*get_handler())(void); /* Expect: here */
