#ifndef MYASSERT_H
#define MYASSERT_H

#include <assert.h>

void assert_failed(const char *expr);
void assert_trace(int value);

/* Every build drops the library's assert, but the tracing level reads the
   condition twice. */
#undef assert
#if MY_ASSERT_LEVEL > 1
#define assert(e) (assert_trace(e), (e) ? (void)0 : assert_failed(#e))
#else
#define assert(e) ((void)(e))
#endif

#endif
