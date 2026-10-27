#ifndef MYASSERT_H
#define MYASSERT_H

#include <assert.h>

void assert_failed(const char *expr);

/* Every build drops the library's assert, and each level defines its own,
   both evaluating the condition once. */
#undef assert
#if MY_ASSERT_LEVEL > 0
#define assert(e) ((e) ? (void)0 : assert_failed(#e))
#else
#define assert(e) ((void)(e))
#endif

#endif
