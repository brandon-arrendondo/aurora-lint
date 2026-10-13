/*
 * Rule: CON05-C
 * Source: testcases
 * Status: FAIL - Should trigger CON05-C violation
 *
 * A macro that names the library function in its own replacement list still
 * calls that function: the preprocessor does not expand a macro inside its
 * own replacement. The counting fputs blocks while the mutex is held.
 */

#include <stdio.h>
#include <threads.h>

extern unsigned long lines_out;

#define fputs(s, f) (lines_out++, fputs(s, f))

mtx_t m;

void counted(const char *s) {
  mtx_lock(&m);
  fputs(s, stdout);
  mtx_unlock(&m);
}
