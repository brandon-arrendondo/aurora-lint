/*
 * Rule: DCL37-C
 * Status: PASS - an identifier starting with an underscore and a lowercase
 * letter is reserved only at file scope; these are declared in blocks.
 */

int sum(const int *v, int n) {
  int _total = 0;
  for (int _i = 0; _i < n; _i++) {
    _total += v[_i];
  }
  return _total;
}
