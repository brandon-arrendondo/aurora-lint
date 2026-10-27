/*
 * Rule: DCL37-C
 * Status: FAIL - a name reserved for any use stays reserved as a structure
 * member and as a label.
 * Expect: count=3
 */

struct header {
  unsigned _Length; /* Expect: here */
  unsigned char *__payload; /* Expect: here */
};

int drain(int n) {
  while (n > 0) {
    n--;
  }
_Done: /* Expect: here */
  return n;
}
