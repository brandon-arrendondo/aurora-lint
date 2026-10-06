/* A non-ASCII name in a macro body must not panic the macro-shape reader. */
#define A(e) (éf() || abort())
void abort(void);
int f(int a) {
  A(a);
  return 0;
}
