/* Malformed: the macro body is missing its closing parenthesis. */
#define A(e) (éf() || abort()
void abort(void);
int f(int a) {
  A(a);
  return 0;
}
