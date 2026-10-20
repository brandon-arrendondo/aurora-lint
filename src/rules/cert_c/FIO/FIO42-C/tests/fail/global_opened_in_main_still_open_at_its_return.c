/*
 * Rule: FIO42-C
 *
 * Status: FAIL - Should trigger FIO42-C violation
 *
 * main opens the log into a file-scope variable and returns with it still
 * open; nothing closes it before the program ends.
 */
#include <stdio.h>

FILE *g_log;

int main(void)
{
    g_log = fopen("log", "a");
    if (g_log == NULL)
        return 1;
    fputs("started\n", g_log);
    return 0;
}
