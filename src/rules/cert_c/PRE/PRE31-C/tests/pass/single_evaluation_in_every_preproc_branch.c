/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger PRE31-C violation
 *
 * Both definitions of LOG_VALUE evaluate their argument exactly once, so
 * the side effect runs once whichever branch is compiled.
 */

int log_int(int v);

#ifdef QUIET
#define LOG_VALUE(x) ((void)(x))
#else
#define LOG_VALUE(x) log_int(x)
#endif

void consume(int *counter)
{
    LOG_VALUE((*counter)++);
}
