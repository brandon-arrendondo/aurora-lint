/*
 * Rule: DCL37-C
 * Status: FAIL - include guards spelled with a leading underscore and an
 * uppercase letter, or with two underscores, are reserved identifiers. Both
 * end in _H and look nothing like a feature-test macro.
 * Expect: count=2
 */

#ifndef _FOO_H
#define _FOO_H /* Expect: here */

#ifndef __FOO_H__
#define __FOO_H__ /* Expect: here */

int foo(void);

#endif
#endif
