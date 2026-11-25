/*
 * Rule: DCL37-C
 * Status: PASS - an unknown calling-convention macro sends the parse of this
 * function-pointer typedef into recovery, which leaves it reading as
 * `typedef const char *_lpSubKey, _ulOptions, DWORD`. Those names are the
 * prototype's parameters, in a scope of their own, not typedef names at
 * file scope, so a leading underscore and a lowercase letter reserve
 * nothing here.
 */

typedef LONG (WINAPI * PFN_Open)(HKEY hKey, const char* _lpSubKey, DWORD _ulOptions, DWORD samDesired);

int opened;
