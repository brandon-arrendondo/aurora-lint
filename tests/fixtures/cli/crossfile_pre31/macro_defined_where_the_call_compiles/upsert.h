#ifndef UPSERT_H
#define UPSERT_H

struct upsert;

#ifndef OMIT_UPSERT
struct upsert *upsert_new(struct upsert *, int);
#else
#define upsert_new(a, b) ((struct upsert *)0)
#endif

#endif
