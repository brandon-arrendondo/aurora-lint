/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger PRE31-C violation
 *
 * `FOO` is spelled like a macro but is declared as a function and defined
 * as a macro nowhere, so `FOO(i++)` is an ordinary call: its argument is
 * evaluated exactly once.
 */

int FOO(int v);

int bump(int i)
{
    return FOO(i++);
}
