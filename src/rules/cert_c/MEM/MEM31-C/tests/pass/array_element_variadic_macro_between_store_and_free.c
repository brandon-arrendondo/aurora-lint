/*
 * Rule: MEM31-C
 * Source: regression
 * Status: PASS - a variadic logging macro that expands to nothing sits between the store and the free
 *
 * The macro's arm is read like any other definition: its body never names
 * the array.
 */
#include <stdlib.h>
#include <string.h>
#define log_msg(args...) do { } while (0)

int f(void){ char *p[16]; unsigned i, n = 0;
 p[n] = malloc(8); n++; log_msg("stored %u", n);
 for (i = 0; i < n; i++) free(p[i]); return 0; }
