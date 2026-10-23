/*
 * Rule: MSC17-C
 * Source: synthetic
 * Status: PASS under the default and strict presets; VIOLATION under pedantic
 * Expect: default=clean strict=clean pedantic=violation
 *
 * Each section ends in a call that never returns, so control cannot reach
 * the next label: exit, abort, longjmp, _Exit, quick_exit, a function the
 * file declares _Noreturn, and an if/else whose arms both end that way.
 * The default and strict presets trust the C library's noreturn contract
 * and the keyword. The pedantic preset trusts neither without a declared
 * C library, and this fixture declares none, so every section there still
 * falls through as far as the scan can tell.
 */
#include <setjmp.h>
#include <stdlib.h>

_Noreturn void die(const char *message);
void work(int step);

static jmp_buf env;

void dispatch(int op)
{
    switch (op) {
    case 1:
        work(1);
        exit(1);
    case 2:
        work(2);
        abort();
    case 3:
        work(3);
        longjmp(env, 1);
    case 4:
        work(4);
        _Exit(2);
    case 5:
        work(5);
        quick_exit(3);
    case 6:
        work(6);
        die("bad op");
    case 7:
        if (op > 0) {
            exit(1);
        } else {
            abort();
        }
    default:
        work(0);
        break;
    }
}
