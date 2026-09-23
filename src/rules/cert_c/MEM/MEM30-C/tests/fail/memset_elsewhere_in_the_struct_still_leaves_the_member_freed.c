/* The other side of an earlier fix: a clearing call only forgets the
 * members it actually overwrites. Each function below is a real defect and
 * must still be reported. */
#include <stdlib.h>
#include <string.h>

struct Rec {
  char *a;
  char pad[8];
  unsigned char *start;
  unsigned char *end;
};

/* The memset covers a different member, so `a` still holds freed storage. */
void other_member(struct Rec *r) {
  free(r->a);
  memset(&r->pad, 0, sizeof(r->pad));
  free(r->a);
}

/* A length read OUT of the object is an ordinary length, not the
 * "zero to the end of the struct" span: it says nothing about how far past
 * `pad` the write reaches, so `a` keeps its freed state.
 *
 * This is the case that earns the address-taken requirement in
 * `clearing_extent::spans_to_object_end` -- with that requirement removed,
 * `r->end - r->start` reads as the span idiom and this double free goes
 * unreported. A length ending in a literal (`r->n - 1`) does NOT exercise
 * it, because the literal already fails the lvalue test. */
void length_read_from_the_object(struct Rec *r) {
  free(r->a);
  memset(&r->pad, 0, r->end - r->start);
  free(r->a);
}

/* Clearing THROUGH a freed pointer is itself a write to freed memory: the
 * call is reported before its clearing effect is applied. */
void clear_through_freed_pointer(void) {
  char *p = malloc(8);
  free(p);
  memset(p, 0, 8);
}
