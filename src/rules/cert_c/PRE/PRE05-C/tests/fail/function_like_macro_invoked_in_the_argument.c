/*
 * Rule: PRE05-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger PRE05-C violation
 *
 * min followed by ( in the argument is an invocation that expanding first
 * would replace; STR stringizes it as written.
 */

#define min(a, b) ((a) < (b) ? (a) : (b))
#define STR(x) #x

const char *s = STR(min(1, 2));
