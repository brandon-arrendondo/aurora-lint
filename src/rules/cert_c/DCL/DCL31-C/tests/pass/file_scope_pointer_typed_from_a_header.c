/*
 * Rule: DCL31-C
 * Status: PASS - Should NOT trigger DCL31-C violation
 */

/*
 * Reason: `LONG (*hook)(HKEY);` at file scope declares `hook`, a function
 * pointer, though `LONG` and `HKEY` come from a header the scan does not
 * show and tree-sitter reads the line as a call of `LONG`: no expression
 * statement stands at file scope. A call through it is declared.
 */

#include <windows.h>

LONG (*hook)(HKEY);
LONG (*reset)();

LONG run(HKEY key)
{
    return hook(key) + reset();
}
