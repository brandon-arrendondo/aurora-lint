/*
 * Rule: FIO42-C
 *
 * Status: PASS - Should NOT trigger FIO42-C violation
 *
 * Neither callee has a body in the scan: one is defined in another
 * translation unit, the other is reached through a pointer. Either may close
 * or keep the stream, so handing it over ends this function's obligation.
 */
#include <stdio.h>

void archive_close(FILE *f);

struct ops {
    void (*done)(FILE *f);
};

void open_handed_to_another_unit(const char *path)
{
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return;
    archive_close(f);
}

void open_handed_through_a_pointer(const struct ops *ops, const char *path)
{
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return;
    ops->done(f);
}
