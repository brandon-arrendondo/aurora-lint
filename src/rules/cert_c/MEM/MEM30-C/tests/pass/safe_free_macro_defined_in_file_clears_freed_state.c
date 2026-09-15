/*
 * Rule: MEM30-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Description: A "safe free" macro — free + `= NULL` in one function-like
 * macro (curl `Curl_safefree`, mosquitto `mosquitto_FREE` / `SAFE_FREE`) —
 * defined in the scanned file itself. Every later free of the same pointer
 * is `free(NULL)`, which is not a double-free. Before this case the rule only
 * consulted the `-d` prescan's macro table for the `= NULL`, so a scan of one
 * file with no `-d` saw the free (name contains FREE) but never the null,
 * and reported both later frees as "freed multiple times".
 */

#include <stdlib.h>

#define my_safefree(ptr) \
  do {                   \
    free(ptr);           \
    (ptr) = NULL;        \
  } while(0)

void f(void)
{
  char *p = malloc(10);
  my_safefree(p);
  my_safefree(p);
  free(p);
}
