/* Malformed: a stray non-ASCII character sits in the #if condition. */
int f(int a) {
  if (a &&
#if a € b
      a > 1
#else
      a > 2
#endif
     ) return 1;
  return 0;
}
