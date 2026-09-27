/*
 * Rule: PRE05-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger PRE05-C violation
 *
 * min is only a function-like macro, and a function-like macro name that is
 * not followed by ( is not expanded (C11 6.10.3p10). Stringizing or pasting
 * it gives "min" and min_count whether or not it is expanded first.
 */

#define min(a, b) ((a) < (b) ? (a) : (b))
#define STR(x) #x
#define CAT(a, b) a##b

const char *s = STR(min);
int CAT(min, _count);
