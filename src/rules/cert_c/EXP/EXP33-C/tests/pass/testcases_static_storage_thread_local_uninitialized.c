/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation
 */

/*
 * Rule: EXP33-C - Do not read uninitialized memory
 * Status: PASS
 * Reason: The variable is a `_Thread_local int` with no initializer. Objects with static or thread
 *         storage duration are zero-initialized when they have no
 *         initializer (C11 6.7.9p10), so every read below sees a determinate
 *         value. This fixture used to assert the opposite.
 */

#include <stdio.h>

/* Well-defined: Thread-local storage uninitialized */
_Thread_local int thread_data;  /* Uninitialized thread-local */

void unsafe_thread_function(void) {
    thread_data += 10;  /* Uses uninitialized thread-local data */
    printf("Thread data: %d\n", thread_data);
}

int main(void) {
    unsafe_thread_function();
    return 0;
}