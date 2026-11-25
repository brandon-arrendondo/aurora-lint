/*
 * Rule: CON40-C
 * Status: PASS - an unknown calling-convention macro sends the parse of this
 * function-pointer typedef into recovery, which leaves it reading as
 * `typedef _Atomic int pending, DWORD`. `DWORD` is the next parameter's
 * type, not a name for an atomic type, so `total` is not atomic and reading
 * it twice is one ordinary expression.
 */

typedef LONG (WINAPI * PFN_Add)(HKEY hKey, _Atomic int pending, DWORD count);

DWORD total;

void bump(void)
{
    total = total + 1;
}
