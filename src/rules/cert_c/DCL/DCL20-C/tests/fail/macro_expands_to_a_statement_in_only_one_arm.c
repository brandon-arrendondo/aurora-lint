/*
 * Rule: DCL20-C
 * Source: aurora-lint
 * Status: FAIL - in one configuration the macro expands to a type
 * Expect: count=1
 *
 * Under NDEBUG, `GUARDED(int) compute();` declares `compute` old-style, so
 * the statement is not a call in every build.
 */

#ifndef NDEBUG
#define GUARDED(t) if (sizeof(t))
#else
#define GUARDED(t) t
#endif

GUARDED(int) compute(); /* Expect: here */
