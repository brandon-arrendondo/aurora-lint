/* A combining mark ending the word before a parenthesis that a #if opens inside must not panic the arm chooser. */
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
