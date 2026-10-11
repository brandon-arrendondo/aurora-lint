/*
 * Rule: POS34-C
 * Source: Maintainer ruling, POS34-C/2026-10-07/options
 * Status: PASS under the default preset; VIOLATION under strict and pedantic
 * Expect: default=clean strict=violation pedantic=violation
 */

#include <stdlib.h>
#include <unistd.h>

void run_child(const char *var) {
  char env[1024];
  snprintf(env, sizeof(env), "TEST=%s", var);
  putenv(env);
  execl("/bin/true", "true", (char *)0);
  _exit(127);
}
