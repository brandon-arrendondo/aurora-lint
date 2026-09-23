/*
 * Rule: EXP10-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP10-C violation
 * Description: A call nested in another call's argument list is sequenced
 * before the outer call's body (C11 6.5.2.2p10), so outer(inner(x)) is not
 * a pair of unsequenced side effects, whatever else is in the expression.
 * The sqlite3_errcode(sqlite3_context_db_handle(ctx)) / curlx_ptimediff_ms(
 * Curl_pgrs_now(data), ...) shape, from a real-world regression.
 */

struct ctx;
extern struct ctx *context_db_handle(struct ctx *c);
extern int errcode(struct ctx *db);
extern long now_ms(void);
extern long diff_ms(long a, long b);
extern void write_reg(int reg, unsigned value);
extern unsigned make_value(int cpu, int vector);

int f(struct ctx *c, long start, int cpu) {
  int rc = errcode(context_db_handle(c)) + 1;
  long elapsed = diff_ms(now_ms(), start) * 2;
  /* sel4's single-real-writer-nested shape: one side-effecting call with
     everything else nested as its arguments. */
  write_reg(3, make_value(cpu, 0x20));
  return rc + (int)elapsed;
}
