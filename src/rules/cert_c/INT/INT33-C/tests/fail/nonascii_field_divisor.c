/* A divisor field with a multi-byte name: its abbreviation is taken by character, not byte, so the scan does not panic. */

struct frac { int ééééé; };

int scale(int n, struct frac *f)
{
  return n / f->ééééé;
}
