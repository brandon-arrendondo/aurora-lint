/*
 * Rule: DCL31-C
 * Source: task 1040 (sqlite src/vdbeapi.c:1285)
 * Status: PASS - neither the enclosing function nor the attribute's own
 * argument is an undeclared call.
 *
 * Two findings came out of this one site. The `#if` in the middle of
 * nullMem's declarator collapses the enclosing function definition into an
 * ERROR node, so `columnNullValue` was never recorded as declared and both
 * of its call sites were flagged. And the grammar parses an attribute's
 * argument list as ordinary expressions, so `aligned(8)` inside
 * `__attribute__((aligned(8)))` read as a call to an undeclared `aligned`.
 */

typedef struct Mem Mem;

static const Mem *columnNullValue(void){
  static const Mem nullMem
#if defined(SQLITE_DEBUG) && defined(__GNUC__)
    __attribute__((aligned(8)))
#endif
    = { 0 };
  return &nullMem;
}

static Mem *columnMem(int i){
  if( i==0 ) return (Mem*)columnNullValue();
  return (Mem*)columnNullValue();
}
