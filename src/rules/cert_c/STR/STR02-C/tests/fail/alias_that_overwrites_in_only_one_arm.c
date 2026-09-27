/*
 * Rule: STR02-C
 * Source: custom
 * Status: FAIL - Should trigger STR02-C violation
 * Description: PUT is strcpy when FRESH is defined and strcat otherwise.
 * Without FRESH it appends to the tainted cmd, which then reaches
 * system(). A copy that overwrites clears taint only if every build's PUT
 * overwrites.
 */

#include <stdlib.h>
#include <string.h>

#ifdef FRESH
#define PUT strcpy
#else
#define PUT strcat
#endif

void run(void)
{
    char cmd[256];
    char *env = getenv("CMD");
    strcpy(cmd, env);
    PUT(cmd, " --safe");
    system(cmd);
}
