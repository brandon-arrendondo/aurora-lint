/*
 * Rule: MEM30-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Description: my_safefree has a definition per build, and each one frees
 * and then nulls its argument, so in either build the trailing free(p) is
 * free(NULL). A null that every live definition performs is still a fact of
 * the macro.
 */

#include <stdlib.h>

void trace_free(void *p);

#ifdef TRACK_FREES
#define my_safefree(ptr) \
  do {                   \
    trace_free(ptr);     \
    free(ptr);           \
    (ptr) = NULL;        \
  } while(0)
#else
#define my_safefree(ptr) \
  do {                   \
    free(ptr);           \
    (ptr) = NULL;        \
  } while(0)
#endif

void f(void)
{
  char *p = malloc(10);
  if (p == NULL)
    return;
  my_safefree(p);
  free(p);
}
