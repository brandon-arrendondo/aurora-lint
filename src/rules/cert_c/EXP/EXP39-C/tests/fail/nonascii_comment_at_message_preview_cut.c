/* A non-ASCII comment across the 50-byte message preview cut must not panic. */
void f(void) {
  float x = 0.0f;
  int *ip = (int *)/*  éééééééééééééééééééééééééééééé */&x;
  (*ip)++;
}
