/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: the call sits in the #else arm of the chain whose #if arm
 * defines the version that drops its argument, so the two never compile
 * together; the version beside the call evaluates it once.
 */

void record(int);

#if LOG_LEVEL == 0
#define LOG_VALUE(v) ((void)0)
#else
#define LOG_VALUE(v) record(v)

void step(int *counter) {
    LOG_VALUE((*counter)++);
}
#endif
