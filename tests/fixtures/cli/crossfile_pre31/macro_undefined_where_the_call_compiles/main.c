#include "upsert.h"

/* The whole file compiles only where upsert_new is the function. */
#ifndef OMIT_UPSERT
struct upsert *upsert_dup(struct upsert *p, int n)
{
    return upsert_new(p, n++);
}
#endif
