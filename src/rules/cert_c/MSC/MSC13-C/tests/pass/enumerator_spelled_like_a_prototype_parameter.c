/*
 * Rule: MSC13-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger MSC13-C violation
 *
 * `idle` is an enumerator where `m` is declared: the prototype's parameter
 * and another function's parameter spelled the same are not in scope
 * there, so `m = idle` is a default (MSC13-EX1) that every path overwrites.
 */

enum mode { idle = 0, busy = 1 };

int get(void);
void prototype(int idle);

void other(int idle)
{
    (void)idle;
}

int f(void)
{
    enum mode m = idle;
    m = get();
    return m;
}
