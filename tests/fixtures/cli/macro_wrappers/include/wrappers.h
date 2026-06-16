/* Lowercase function-like allocation/free wrappers, mirroring curl's
 * curlx_free/curlx_calloc (curl_setup.h). These are function-like macros, not
 * object-like aliases, so only ProjectContext.function_macros (collected by the
 * prescan pre-pass) lets DCL31-C recognize their invocations as macro
 * expansions rather than undeclared-function calls. */
#ifndef WRAPPERS_H
#define WRAPPERS_H

#define xfree(ptr)          free(ptr)
#define xcalloc(n, sz)      calloc((n), (sz))

#endif
