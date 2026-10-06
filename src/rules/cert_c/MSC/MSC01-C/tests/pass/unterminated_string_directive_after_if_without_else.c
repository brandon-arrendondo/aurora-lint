/* Malformed: the directive holds an unterminated non-ASCII string. */
int f(int a) {
  if (a == 1) { a = 2; }
#define X "é
  return a;
}
