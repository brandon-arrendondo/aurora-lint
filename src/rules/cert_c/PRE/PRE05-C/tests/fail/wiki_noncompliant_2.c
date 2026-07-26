/*
 * Rule: PRE05-C
 * Source: wiki
 * Status: FAIL - Should trigger PRE05-C violation
 */

#define str(s) #s
#define foo 4

str(foo)