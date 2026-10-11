/*
 * Rule: POS34-C
 * Source: Maintainer ruling, POS34-C/2026-10-07/options
 * Status: FAIL - a path after the call returns, so the exit-path option does not apply
 */

#include <stdlib.h>

void run(const char *var, int fast) {
  char env[1024];
  snprintf(env, sizeof(env), "TEST=%s", var);
  putenv(env);
  if (fast) {
    return;
  }
  exit(0);
}
