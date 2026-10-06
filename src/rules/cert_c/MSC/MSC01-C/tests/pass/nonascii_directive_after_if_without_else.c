/* A non-ASCII character in a directive after an `if` with no `else` must not panic the directive scan. */
int f(int a) {
  if (a == 1) { a = 2; }
#define X é
  return a;
}
