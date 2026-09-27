/*
 * Rule: PRE05-C
 * Source: testcases
 * Status: FAIL - Should trigger PRE05-C violation
 *
 * W evaluates its parameter in one conditional definition and pastes it in
 * the other. Either may be the one compiled, and where the pasting one is,
 * W(LVL) builds w_LVL, not w_3.
 */

#define LVL 3

#ifdef A
#define W(c) ((c) < 0)
#else
#define W(c) (w_ ## c)
#endif

int w_LVL;

int v = W(LVL);  /* VIOLATION */
