/*
 * Rule: DCL37-C
 * Status: PASS - members and labels each have a name space of their own, which
 * the file-scope reservation of an underscore followed by a lowercase letter
 * does not reach.
 */

struct header {
  unsigned _length;
  unsigned char *_payload;
};

int drain(int n) {
  while (n > 0) {
    n--;
  }
_done:
  return n;
}
