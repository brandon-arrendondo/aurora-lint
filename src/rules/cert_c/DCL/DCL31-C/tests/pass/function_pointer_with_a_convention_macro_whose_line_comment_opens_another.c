/*
 * Rule: DCL31-C
 * Status: PASS - Should NOT trigger DCL31-C violation
 */

/*
 * Reason: `CC` is `__stdcall`; the `/*` after it is inside a `//` comment,
 * which closes nothing and opens nothing. So `LONG (CC *del)(HKEY);`
 * declares the function pointer `del`, and the call through it is
 * declared.
 */

#include <windows.h>

#define CC __stdcall // see /* the ABI

LONG run(HKEY key)
{
    LONG (CC *del)(HKEY);

    return del(key);
}
