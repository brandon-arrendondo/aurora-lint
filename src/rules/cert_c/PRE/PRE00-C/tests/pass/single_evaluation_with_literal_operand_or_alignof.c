/*
 * Rule: PRE00-C
 * Source: testcases
 * Status: PASS - Should not trigger PRE00-C violation
 *
 * Each macro evaluates its parameter once and has no side effect of its
 * own: the "c++" is a string literal, #e only spells the argument, and
 * _Alignof never evaluates its operand.
 */

void log_line(const char *language, int value);
void fail(const char *expression);

#define LOG_CPP(x) log_line("c++", (x)) /* x-- would be a side effect */
#define CHECK(e) ((e) ? (void)0 : fail(#e))
#define ALIGN_MASK(x) ((x) & (_Alignof(x) - 1))

int use(int v)
{
    LOG_CPP(v);
    CHECK(v > 0);
    return ALIGN_MASK(v);
}
