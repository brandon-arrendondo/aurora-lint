/*
 * Rule: CON05-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON05-C violation
 *
 * A function-like macro the project defines under a library function's name
 * replaces every later call of that name. Here "mtx_lock" takes the
 * project's own lock, which this rule does not read as a C11 mutex.
 * "fputs" becomes the project's buffered append, which does not block under
 * the real mutex.
 */

#include <stdio.h>
#include <threads.h>

int my_lock(void *m);
int my_unlock(void *m);
int buffer_append(const char *s, void *f);

mtx_t real;

void through_a_project_fputs(const char *s) {
  mtx_lock(&real);
#define fputs(s, f) buffer_append(s, f)
  fputs(s, stdout);
#undef fputs
  mtx_unlock(&real);
}

#define mtx_lock(m) my_lock(m)
#define mtx_unlock(m) my_unlock(m)

void under_a_project_lock(const char *s, void *own) {
  mtx_lock(own);
  fputs(s, stdout);
  mtx_unlock(own);
}
