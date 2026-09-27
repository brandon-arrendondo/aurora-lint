/*
 * Rule: EXP33-C
 * Source: custom
 * Status: PASS - Should NOT trigger EXP33-C violation
 * Description: FETCH has a definition per build and each one assigns its
 * first argument, so x is initialized after FETCH(x, 3) in either build. An
 * output that every live definition writes is still the macro's output.
 */

int read_slow(int v);

#ifdef FAST_PATH
#define FETCH(out, v) ((out) = (v))
#else
#define FETCH(out, v) ((out) = read_slow(v))
#endif

int f(void)
{
  int x;
  FETCH(x, 3);
  return x;
}
