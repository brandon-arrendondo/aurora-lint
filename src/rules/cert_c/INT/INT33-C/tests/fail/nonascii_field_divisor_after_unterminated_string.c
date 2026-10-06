/* The same field after an unterminated string literal, which error recovery turns into a differently shaped tree. */

struct frac { int ééééé; };

int scale(int n, struct frac *f)
{
  const char *s = "unterminated;
  return n / f->ééééé;
}
