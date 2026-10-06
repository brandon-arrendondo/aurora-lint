/* Malformed: the non-ASCII block comment is never closed. */
int f(int x) {
  switch (x) {
  case 1: x++; /* €
    deliberate_fall_through;
  case 2: break;
  }
  return x;
}
