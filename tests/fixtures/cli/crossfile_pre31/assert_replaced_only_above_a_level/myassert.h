#ifndef MYASSERT_H
#define MYASSERT_H

#include <assert.h>

void assert_failed(const char *expr);

/* Only a build that asks for checking replaces the library's assert. */
#if MY_ASSERT_LEVEL > 0
#undef assert
#define assert(e) ((e) ? (void)0 : assert_failed(#e))
#endif

#endif
