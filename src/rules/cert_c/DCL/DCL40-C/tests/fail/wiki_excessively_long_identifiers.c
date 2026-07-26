/*
 * Rule: DCL40-C
 * Source: wiki
 * Status: FAIL - Should trigger DCL40-C violation
 */

/* In bashline.h */
/* UB 14, UB 30 */
extern char * bash_groupname_completion_function(const char *, int);

/* In a.c */
#include "bashline.h"

void f(const char *s, int i) {
  bash_groupname_completion_function(s, i);  /* UB 37 */
}

/* In b.c */
int bash_groupname_completion_funct;  /* UB 14, UB 30 */