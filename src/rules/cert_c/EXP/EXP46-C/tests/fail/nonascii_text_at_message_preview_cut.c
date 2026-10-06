/* Non-ASCII text across the 40- and 60-byte message preview cuts must not panic. */
int f(int a, int b) {
  return (a > 1) | (b > 2 && a != 0 && b != 1 && "ééééééééééééééééééééééééééééééééééé" != 0);
}
