/*
 * Rule: CWE-272
 * Status: FAIL - a Win32 registry name this file defines only in some
 *         builds is still the Win32 API in the others: a definition under
 *         `#ifdef _WIN32_WCE` and a `static` one under `#if 0` leave the real
 *         call wherever they are not compiled
 */

typedef void *HKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;
typedef const unsigned char *LPCBYTE;

#define HKEY_LOCAL_MACHINE ((HKEY)(unsigned long)0x80000002)
#define REG_DWORD 4

#ifdef _WIN32_WCE
LONG RegDeleteValueA(HKEY key, LPCSTR name)
{
    (void)key;
    (void)name;
    return 0;
}
#else
LONG RegDeleteValueA(HKEY, LPCSTR);
#endif

#if 0
static LONG RegSetValueExA(HKEY k, LPCSTR n, DWORD r, DWORD t, LPCBYTE d, DWORD c)
{
    return 0;
}
#endif
LONG RegSetValueExA(HKEY, LPCSTR, DWORD, DWORD, LPCBYTE, DWORD);

void f(void)
{
    DWORD one = 1;
    RegDeleteValueA(HKEY_LOCAL_MACHINE,  /* VIOLATION: the API outside _WIN32_WCE */
                    "v");
    RegSetValueExA(HKEY_LOCAL_MACHINE,  /* VIOLATION: the static is never compiled */
                   "Setting", 0, REG_DWORD, (LPCBYTE)&one, sizeof one);
}
