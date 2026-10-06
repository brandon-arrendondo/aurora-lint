/* Malformed: the non-ASCII string is never closed. */
int f(int a, int b) {
  return (a > 1) | (b > 2 && a != 0 && b != 1 && "ééééééééééééééééééééééééééééééééééé != 0);
}
