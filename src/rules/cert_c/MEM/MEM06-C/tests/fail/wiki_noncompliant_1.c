/*
 * Rule: MEM06-C
 * Source: wiki
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: CERT's noncompliant example, with the secret's use made explicit:
 * the rule's written scope calls a buffer sensitive when it reaches a
 * declared credential sink, so the example hands `secret` to crypt(). The
 * block is never locked and core dumps stay enabled.
 */

#include <crypt.h>
#include <stdlib.h>
#include <string.h>

void hash_secret(size_t size, const char *salt) {
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
