/* A combining mark ends the word before the parenthesis a #if opens inside. */
int f(int a) {
  if́ (a &&
#if 1
      a > 1
#else
      a > 2
#endif
     ) return 1;
  return 0;
}
