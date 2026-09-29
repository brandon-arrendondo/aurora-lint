/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: PASS - Should not trigger PRE31-C violation
 *
 * TAGGED_LOG hands its arguments to LOG, which passes them straight to a
 * function: each is evaluated exactly once, so i++ is safe here.
 */

void log_message(int level, const char *format, ...);

#define LOG(level, ...) log_message(level, __VA_ARGS__)

#define TAGGED_LOG(level, ...) LOG(level, "tagged: " __VA_ARGS__)

int next(int i)
{
    TAGGED_LOG(2, "at %d", i++);
    return i;
}
