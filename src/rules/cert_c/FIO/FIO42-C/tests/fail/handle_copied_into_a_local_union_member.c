/*
 * Rule: FIO42-C
 *
 * Status: FAIL - Should trigger FIO42-C violation
 *
 * Storing the stream in a member of a local union keeps it inside this
 * function: the union dies with the call, and nothing closes the stream.
 */
#include <stdio.h>

union stream_slot {
    FILE *in;
    FILE *out;
};

void stage(const char *path)
{
    union stream_slot slot;
    FILE *f = fopen(path, "r");
    slot.in = f;
    {
        FILE *g = slot.out;
        fputc('x', g);
    }
}
