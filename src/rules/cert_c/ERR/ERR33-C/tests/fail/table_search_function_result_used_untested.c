/*
 * Rule: ERR33-C
 * Status: FAIL - strchr() returns NULL when the character is not found, and
 * the result is used without that test.
 */

#include <string.h>

size_t key_length(const char *entry) {
    const char *eq = strchr(entry, '=');
    return (size_t)(eq - entry);
}
