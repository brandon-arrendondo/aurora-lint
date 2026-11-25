/*
 * Rule: MEM33-C
 * Status: PASS - an unknown calling-convention macro sends the parse of this
 * function-pointer typedef into recovery, which leaves it reading as
 * `typedef struct flex { ... } f, DWORD`. `DWORD` is the next parameter's
 * type, not a name for the structure with a flexible array member, so
 * assigning one `DWORD` to another copies no such structure.
 */

typedef LONG (WINAPI * PFN_Take)(HKEY hKey, struct flex { int n; int d[]; } f, DWORD count);

DWORD a, b;

void copy(void)
{
    a = b;
}
