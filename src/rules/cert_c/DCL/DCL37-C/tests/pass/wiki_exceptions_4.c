/*
 * Rule: DCL37-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

/*
  The following declarations of reserved identifiers exist in the glibc implementation of
  <stdio.h>. The original source code may be found at:
  https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=include/stdio.h;hb=HEAD
*/
 
#  define __need_size_t
#  include <stddef.h>
/* Generate a unique file name (and possibly open it).  */
extern int __path_search (char *__tmpl, size_t __tmpl_len,
              const char *__dir, const char *__pfx,
              int __try_tempdir);