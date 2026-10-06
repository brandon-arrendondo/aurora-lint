/*
 * Rule: ENV03-C
 * Source: testcases
 * Status: FAIL - Should trigger ENV03-C violation
 *
 * The writer reads through a function-like macro, defined inside the
 * function, that stringifies its argument (`#_name`) and calls sscanf. A
 * macro using `#` cannot be expanded, but it still calls what its
 * replacement list calls, so the writer is tainted and the sink is flagged.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *env03_strmacro_cmd;

static void env03_strmacro_init(const char *key, const char *param) {
    static char buf[100];

#define PARSE_WORD(_name, dst) \
	(strcmp(#_name, key) == 0 && sscanf (param, "%99s", dst) == 1)

    if (PARSE_WORD(command, buf)) {
        env03_strmacro_cmd = buf;
    }
}

static void env03_strmacro_execute(void) {
    char *data = env03_strmacro_cmd;
    system(data);
}
