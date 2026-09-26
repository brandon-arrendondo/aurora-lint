/*
 * Rule: PRE05-C
 * Source: wiki
 * Status: PASS - Should NOT trigger PRE05-C violation
 *
 * The definition from CERT's noncompliant example, on its own. PRE05-C's
 * defect is at an invocation that passes a macro name to a pasted or
 * stringized parameter (tests/fail/wiki_noncompliant_1.c passes __LINE__ to
 * JOIN). A definition nothing invokes that way expands nothing wrongly.
 */

#define JOIN(x, y) x ## y
