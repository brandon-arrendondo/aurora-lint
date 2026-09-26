/*
 * Rule: MEM06-C
 * Source: wiki
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: CERT's POSIX compliant solution: core dumps are disabled with a
 * zero RLIMIT_CORE on the startup path (main) before the secret, which
 * reaches crypt(), is allocated.
 */

#include <sys/resource.h>
#include <crypt.h>
#include <stdlib.h>
#include <string.h>

static void hash_secret(size_t size, const char *salt) {
  char *secret;

  secret = (char *)malloc(size+1);
  if (!secret) {
    return;
  }

  /* Perform operations using secret... */
  crypt(secret, salt);

  memset_s(secret, '\0', size+1);
  free(secret);
  secret = NULL;
}

int main(int argc, char **argv) {
  struct rlimit limit;
  limit.rlim_cur = 0;
  limit.rlim_max = 0;
  if (setrlimit(RLIMIT_CORE, &limit) != 0) {
      return 1;
  }
  hash_secret(64, argv[1]);
  return 0;
}
