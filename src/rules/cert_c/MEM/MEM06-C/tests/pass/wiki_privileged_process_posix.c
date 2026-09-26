/*
 * Rule: MEM06-C
 * Source: wiki
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: CERT's privileged-process compliant solution: core dumps disabled
 * at startup and the page-aligned secret mlock()ed before use.
 */

#include <sys/resource.h>
#include <sys/mman.h>
#include <crypt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void hash_secret(size_t size, const char *salt) {
  long pagesize = sysconf(_SC_PAGESIZE);
  if (pagesize == -1) {
    return;
  }

  char *secret_buf;
  char *secret;

  secret_buf = (char *)malloc(size+1+pagesize);
  if (!secret_buf) {
    return;
  }

  /* mlock() may require that address be a multiple of PAGESIZE */
  secret = (char *)((((intptr_t)secret_buf + pagesize - 1) / pagesize) * pagesize);

  if (mlock(secret, size+1) != 0) {
      return;
  }

  /* Perform operations using secret... */
  crypt(secret, salt);

  if (munlock(secret, size+1) != 0) {
      return;
  }
  secret = NULL;

  memset_s(secret_buf, '\0', size+1+pagesize);
  free(secret_buf);
  secret_buf = NULL;
}

int main(int argc, char **argv) {
  struct rlimit limit = {0, 0};
  if (setrlimit(RLIMIT_CORE, &limit) != 0) {
      return 1;
  }
  hash_secret(64, argv[1]);
  return 0;
}
