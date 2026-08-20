/*
 * Rule: PRE05-C
 * Source: wiki
 * Status: PASS - Should NOT trigger PRE05-C violation
 */

#define xstr(s) str(s)
#define str(s) #s
#define foo 4
