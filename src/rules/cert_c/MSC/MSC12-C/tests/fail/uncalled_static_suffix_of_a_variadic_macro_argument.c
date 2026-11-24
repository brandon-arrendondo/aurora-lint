/*
 * Rule: MSC12-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger MSC12-C violation
 *
 * The `##` in `fmt, ##args` drops the comma when no argument follows; it
 * pastes no name. So the argument `key` handed to the logging macro is no
 * fragment of `is_key_valid`, which nothing calls.
 */

#include <stdio.h>

#define vlog(fmt, args...) printf(fmt, ##args)
#define vdebug(fmt, ...) printf(fmt, ##__VA_ARGS__)

static int is_key_valid(const char *key) { /* VIOLATION */
    return key[0] != '\0';
}

int api(const char *key) {
    vlog("%s\n", key);
    vdebug("%s\n", key);
    return 0;
}
