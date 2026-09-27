/*
 * Rule: EXP33-C
 * Source: custom
 * Status: FAIL - Should trigger EXP33-C violation
 * Description: FETCH assigns its first argument only when FAST_PATH is
 * defined; the other build's definition reads it, so FETCH(x, 3) reads the
 * uninitialized x there. Both definitions are live, and an argument is the
 * macro's output only when every definition writes it. Taking the first
 * definition met counted x as initialized in both builds.
 */

void log_value(int current, int v);

#ifdef FAST_PATH
#define FETCH(out, v) ((out) = (v))
#else
#define FETCH(out, v) log_value((out), (v))
#endif

int f(void)
{
  int x;
  FETCH(x, 3);
  return x;
}
