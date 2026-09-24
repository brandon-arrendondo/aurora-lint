/* The command comes from a global. Whether popen() is flagged depends on
 * every function that writes the global, and its only writer is a static in
 * entry.c. */
#include <stdio.h>

extern char *g_cmd;

void sink(void)
{
    char *data = g_cmd;
    FILE *pipe = popen(data, "w");
    if (pipe != NULL) {
        pclose(pipe);
    }
}
