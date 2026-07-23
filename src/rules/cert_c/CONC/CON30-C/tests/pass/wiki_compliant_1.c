/*
 * Rule: CON30-C
 * Source: wiki
 * Status: PASS - Should NOT trigger CON30-C violation
 */

#include <threads.h>
#include <stdlib.h>
 
/* Global key to the thread-specific storage */
tss_t key;
 
int function(void *dummy) {
  if (add_data() != 0) {
    return -1;	/* Report error */
  }
  print_data();
  free(tss_get(key));
  return 0;
}

/* ... Other functions are unchanged */