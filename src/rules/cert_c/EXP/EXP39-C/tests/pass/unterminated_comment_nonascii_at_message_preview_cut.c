/* Malformed: the non-ASCII comment is never closed. */
void f(void) {
  float x = 0.0f;
  int *ip = (int *)/*  éééééééééééééééééééééééééééééé &x;
  (*ip)++;
}
