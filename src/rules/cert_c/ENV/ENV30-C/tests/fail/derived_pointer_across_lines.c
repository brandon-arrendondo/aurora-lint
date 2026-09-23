/*
 * Rule: ENV30-C
 * Source: real-world
 * Status: FAIL - Should trigger ENV30-C violation
 */

/*
 * strchr returns a pointer INTO the environment string, so writing
 * through it is the same violation as writing through getenv's own
 * return. The call is split across lines here because the text scan this
 * replaced enumerated four spellings of "strchr(env," and matched none of
 * them once a newline got in the way.
 */

#include <stdlib.h>
#include <string.h>

void truncate_path_at_separator(void) {
    char *env = getenv("PATH");

    if (env == NULL) {
        return;
    }

    char *separator = strchr(
        env,
        ':');

    if (separator != NULL) {
        /* VIOLATION: writes into the environment string */
        strcpy(separator, "");
    }
}
