/*
 * Rule: MSC13-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC13-C violation
 */

int *p1;
int *p2;
p1 = foo();
p2 = bar();

if (baz()) {
  return p1;
}
else {
  p2 = p1;
}
return p2;