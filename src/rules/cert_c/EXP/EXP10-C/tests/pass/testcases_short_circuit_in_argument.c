/*
 * Rule: EXP10-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP10-C violation
 * Description: && and || sequence their operands wherever they appear --
 * inside an argument list or a subscript as much as at the top of an
 * expression. lua_assert(ttisfloat(key) || luaV_rawequalobj(a, b)) and
 * assert(!(irq[cpu()] == invalid && pending(cpu()))) (task 1147 mechanism 3).
 */

extern int check(int cond);
extern int is_float(void *k);
extern int raw_equal(void *a, void *b);
extern int cpu_index(void);
extern int ipi_pending(int cpu);
extern int irq_table[8];

int f(void *key, void *v) {
  int a = check(is_float(key) || raw_equal(key, v));
  int b = check(!(irq_table[cpu_index()] == -1 && ipi_pending(cpu_index())));
  int c = irq_table[cpu_index() && ipi_pending(0)];
  return a + b + c;
}
