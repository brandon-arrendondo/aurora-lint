/*
 * Rule: PRE05-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger PRE05-C violation
 *
 * GNU's `, ## __VA_ARGS__` only removes the comma when no variable
 * arguments are given; the arguments themselves are still macro-expanded,
 * so LEVEL reaches log_msg as 3.
 */

#define LEVEL 3
#define log_at(fmt, ...) log_msg(fmt, ##__VA_ARGS__)

void log_msg(const char *fmt, ...);

void report(void) { log_at("level %d", LEVEL); }
