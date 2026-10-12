/*
 * Rule: POS34-C
 * Source: synthetic
 * Status: FAIL - exec returns when it fails, so the path continues past it and the exit-path option does not apply
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int run(char **argv) {
  char env[16] = "A=1";
  putenv(env);
  execv(argv[0], argv);
  return -1;
}
