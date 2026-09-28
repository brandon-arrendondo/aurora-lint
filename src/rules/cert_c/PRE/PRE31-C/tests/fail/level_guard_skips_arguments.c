/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: FAIL - Should trigger PRE31-C violation
 *
 * LOG leaves its do-while before the call when the level is below the
 * threshold, so its arguments are evaluated once or not at all: whether
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

int next(int i)
{
    LOG(2, "at %d", i++); /* VIOLATION */
    return i;
}
