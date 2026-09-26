/*
 * Rule: PRE05-C
 * Source: testcases
 * Status: FAIL - Should trigger PRE05-C violation
 *
 * VERSION_MAJOR is a macro, but STRINGIFY stringizes its parameter, so the
 * result is "VERSION_MAJOR", not "3". Detection keys on the operand
 * parameter and the argument's definition, not on the macros' names.
 */

#define STRINGIFY(x) #x
#define VERSION_MAJOR 3

const char *version_major = STRINGIFY(VERSION_MAJOR);  /* VIOLATION */
