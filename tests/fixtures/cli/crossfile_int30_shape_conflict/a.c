#include <stddef.h>

/* This file's `struct S` has an anonymous `sme` whose `ie` is an array. */
struct S {
    struct {
        unsigned char ie[8];
    } sme;
};

unsigned char *first(struct S *s)
{
    return s->sme.ie;
}
