/*
 * Rule: DCL41-C
 * Source: testcases
 * Status: FAIL - Should trigger DCL41-C violation
 *
 * PREPARE expands to a case label in one configuration and to a statement
 * in the other. In the second, `count = 0;` and the call after it sit
 * before the first case label, so the macro is not treated as a label.
 */

int count;
int reset(int n);

#ifdef USE_LABEL
#define PREPARE case 0:
#else
#define PREPARE count = 0;
#endif

int run(int op) {
  switch (op) {
    PREPARE reset(0);
    case 1:
      return count;
    default:
      return -1;
  }
}
