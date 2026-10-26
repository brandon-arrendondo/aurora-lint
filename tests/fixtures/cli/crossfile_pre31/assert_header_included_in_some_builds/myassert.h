#ifndef MYASSERT_H
#define MYASSERT_H

#include <assert.h>

void assert_failed(const char *expr);

/* The project's assert evaluates its condition in every build. */
#ifdef assert
#undef assert
#endif
#define assert(e) ((e) ? (void)0 : assert_failed(#e))

#endif
