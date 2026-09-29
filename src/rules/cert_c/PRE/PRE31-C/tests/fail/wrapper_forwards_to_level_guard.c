/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: FAIL - Should trigger PRE31-C violation
 *
 * TAGGED_LOG evaluates its arguments once in its own body, but hands them
 * to LOG, which skips them when the level is below the threshold: whether
 * i++ happens depends on the verbosity.
 */

int verbosity;
void log_message(int level, const char *format, ...);

#define LOG(level, ...)                     \
    do {                                    \
        if ((level) < verbosity)            \
            break;                          \
        log_message(level, __VA_ARGS__);    \
    } while (0)

#define TAGGED_LOG(level, ...) LOG(level, "tagged: " __VA_ARGS__)

int next(int i)
{
    TAGGED_LOG(2, "at %d", i++); /* VIOLATION */
    return i;
}
