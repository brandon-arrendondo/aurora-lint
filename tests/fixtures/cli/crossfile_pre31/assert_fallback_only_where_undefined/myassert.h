#ifndef MYASSERT_H
#define MYASSERT_H

void assert_failed(const char *expr);

/* Only a fallback: where <assert.h> came first, its assert stands. */
#ifndef assert
#define assert(e) ((e) ? (void)0 : assert_failed(#e))
#endif

#endif
