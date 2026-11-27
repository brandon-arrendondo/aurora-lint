/*
 * Rule: ENV03-C
 * Source: synthetic
 * Status: FAIL - A command reaches system() through a parameter of a function that returns a pointer
 * Expect: count=1
 *
 * `run` returns a pointer, so its parameter list sits under a pointer
 * declarator. `cmd` is still its parameter, and its only caller passes
 * text read from the environment, so the command is not one the program
 * controls.
 */
#include <stdlib.h>

static char status[8];

char *run(const char *cmd)
{
    if (system(cmd) != 0) /* Expect: here */
        return NULL;
    return status;
}

void start(void)
{
    run(getenv("TOOL_COMMAND"));
}
