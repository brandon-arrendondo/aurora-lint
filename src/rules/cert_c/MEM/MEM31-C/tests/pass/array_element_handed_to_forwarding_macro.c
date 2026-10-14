/*
 * Rule: MEM31-C
 * Source: regression
 * Status: PASS - the element and the counter are handed to a macro that only forwards them to a function
 *
 * hostap's `os_memcpy` is one call to `memcpy` taking each argument whole:
 * the element's value is read, as it would be by `memcpy` itself.
 */
#include <stdlib.h>
#include <string.h>
#define copy_bytes(d, s, n) memcpy((d), (s), (n))

int f(const char *src){ char *p[8]; unsigned i, n = 0;
 p[n] = malloc(8); if (!p[n]) return -1; copy_bytes(p[n], src, 8); n++;
 copy_bytes(p[0], src, n);
 for (i = 0; i < n; i++) free(p[i]); return 0; }
