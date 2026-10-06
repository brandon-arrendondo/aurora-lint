/* A non-ASCII name in a #if condition inside a call must not panic the arm chooser. */
int f(int a) {
  if (a &&
#if é
      a > 1
#else
      a > 2
#endif
     ) return 1;
  return 0;
}
