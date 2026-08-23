/*
 * Rule: API02-C
 * Source: testcases
 * Status: PASS - Should NOT trigger API02-C violation
 *
 * A trailing pointer to a scalar arithmetic type (int/long/size_t/...) is
 * a single-value output parameter, not an unsized array — there is no
 * possible size argument for it anywhere in the signature, so a
 * memory-safe implementation can only ever write one element through it
 * (task 450).
 */

#include <stddef.h>

int curl_easy_recv(void *curl_handle, void *buffer, size_t buflen, size_t *n);
int curl_multi_perform(void *multi_handle, int *running_handles);
int curl_multi_timeout(void *multi_handle, long *milliseconds);
int sqlite3_compile_options(int *pnOpt);
