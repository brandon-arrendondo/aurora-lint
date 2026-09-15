/*
 * Rule: MEM30-C
 * Source: custom
 * Status: FAIL - Should trigger MEM30-C violation
 * Description: The control for the safe-free case next to it in pass/: a
 * function-like macro defined in the scanned file that frees its argument
 * but does NOT null it. Merging the file's own macro table into the rule
 * must not turn every FREE-named macro into a safe free — only a body that
 * assigns the parameter the null pointer constant clears the freed state,
 * so the second invocation here is a genuine double-free.
 */

#include <stdlib.h>

#define my_free(ptr) \
  do {               \
    free(ptr);       \
  } while(0)

void h(void)
{
  char *p = malloc(10);
  my_free(p);
  my_free(p);
}
