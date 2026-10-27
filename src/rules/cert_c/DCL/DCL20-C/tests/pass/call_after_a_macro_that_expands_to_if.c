/*
 * Rule: DCL20-C
 * Source: aurora-lint
 * Status: PASS - a call statement after a macro that expands to `if (...)`
 *
 * `CHECK(ok) flush();` parses as a declaration of `flush` whose type is the
 * invocation `CHECK(ok)`. The macro expands to `if (ok)`, so the statement is
 * a call of `flush`, which is declared with (void), and nothing is declared.
 */

#define CHECK(x) if (x)

void flush(void);

void finish(int ok) {
    CHECK(ok) flush();
}
