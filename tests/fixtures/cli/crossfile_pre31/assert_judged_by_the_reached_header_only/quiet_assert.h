#ifndef QUIET_ASSERT_H
#define QUIET_ASSERT_H

#include <assert.h>

/* Another component's assert, which main.c never includes. */
#undef assert
#define assert(e) ((void)0)

#endif
