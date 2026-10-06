/* A non-ASCII line comment before a fallthrough macro must not panic the blanking pass. */
int f(int x) {
  switch (x) {
  case 1: x++; // €
    deliberate_fall_through;
  case 2: break;
  }
  return x;
}
