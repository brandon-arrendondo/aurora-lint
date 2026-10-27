/*
 * Rule: DCL37-C
 * Status: PASS - a typedef name or enumeration constant declared in a block
 * has block scope, where an underscore followed by a lowercase letter is not
 * reserved.
 */

int sum(int a, int b) {
  typedef long _wide;
  enum { _off, _on } state = _on;
  _wide total = (_wide)a + b;
  return (int)total + (int)state;
}
