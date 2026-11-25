/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: the init-once cache. `sp` has static storage duration, so the
 * struct it points to, and the string stored in that struct, stay reachable
 * through it after every return. A later call returns early and allocates
 * nothing.
 */
#include <stdlib.h>
#include <string.h>

struct settings {
    char *name;
};

void settings_init_once(const char *name)
{
    static struct settings *sp;

    if (sp != NULL)
        return;
    sp = malloc(sizeof *sp);
    if (sp == NULL)
        return;
    sp->name = strdup(name);
}
