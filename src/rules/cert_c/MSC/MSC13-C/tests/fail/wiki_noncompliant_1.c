/*
 * Rule: MSC13-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC13-C violation. The wiki presents this
 * as a bare fragment with no enclosing function (confirmed against the
 * live wiki -- it's shown exactly this way in the source page too), which
 * aurora-lint can't analyze: MSC13-C, like essentially every CERT-C rule in this
 * codebase, operates per function_definition, so a fragment with none is
 * never even reached. Wrapped in a plausible function to make the
 * fragment's actual violation (p2 = bar() is dead: p2 is either
 * unreachable in the if-branch's return, or overwritten with p1 before use
 * in the else-branch, so bar()'s result is never read) analyzable.
 */

extern int *foo(void);
extern int *bar(void);
extern int baz(void);

int *func(void) {
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
}