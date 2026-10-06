/* Three non-static sinks: printf uses whatever reaches each one as a
 * parameter as its format string. Whether it is flagged depends on what
 * every caller passes, and on whether the scanned files are all of the
 * callers there are (the closed_program declaration, ADR-0011). */
#include <stdio.h>

void show_fixed(const char *fmt)
{
    printf(fmt);
}

void show_by_pointer(const char *fmt)
{
    printf(fmt);
}

void show_arg(const char *fmt)
{
    printf(fmt);
}
