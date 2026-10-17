/*
 * Rule: DCL31-C
 * Status: PASS - Should NOT trigger DCL31-C violation
 */

/*
 * Reason: `LONG (WINAPI *hook)(HKEY);` declares `hook`, a function pointer,
 * though tree-sitter reads it as a call of `LONG` with `WINAPI * hook`: a
 * calling convention is never a factor. A call through it is declared, at
 * file scope or in a block.
 */

#include <windows.h>

LONG (WINAPI *hook)(HKEY);

LONG run(HKEY key)
{
    LONG (CALLBACK *reset)(HKEY) = 0;
    LONG (__stdcall *probe)(HKEY);

    return hook(key) + reset(key) + probe(key);
}
