/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: PASS - Should not trigger PRE31-C violation
 *
 * LOG may skip its arguments, but these have no side effects, so whether
 * they are evaluated changes nothing.
 */

int verbosity;
void log_message(int level, const char *format, ...);

#define LOG(level, ...)                     \
    do {                                    \
        if ((level) < verbosity)            \
            break;                          \
        log_message(level, __VA_ARGS__);    \
    } while (0)

int report(int i)
{
    LOG(2, "at %d", i + 1);
    return i;
}
