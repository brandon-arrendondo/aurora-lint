#include "upsert.h"

/* Compiled in every build, the OMIT_UPSERT one, where upsert_new drops its
 * arguments, included. */
struct upsert *upsert_dup(struct upsert *p, int n)
{
    return upsert_new(p, n++);
}
