/*
 * Rule: DCL06-C
 * Source: testcases
 * Status: FAIL - Should trigger DCL06-C violation
 */

/*
 * Rule: DCL06-C - Use meaningful symbolic constants
 * Status: FAIL
 * Reason: The version-accessor exemption (task 1153) keys on the callee's
 *         name; a comparison against any other call's result is still a
 *         magic number.
 */

int queue_depth(void *q);

int overloaded(void *q)
{
    return queue_depth(q) > 3008002;
}
