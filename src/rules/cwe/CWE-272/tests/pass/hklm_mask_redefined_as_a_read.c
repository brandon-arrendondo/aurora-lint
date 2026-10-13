/*
 * Rule: CWE-272
 * Status: PASS - a mask macro defined as a write, undefined and redefined as
 *         a read before the call: only the definition in force at the call
 *         counts, directly and in a wrapper body
 */

typedef void *HKEY;
typedef unsigned long DWORD;
typedef DWORD REGSAM;
typedef long LONG;
typedef const char *LPCSTR;
typedef HKEY *PHKEY;

#define HKEY_LOCAL_MACHINE ((HKEY)(unsigned long)0x80000002)
#define KEY_READ 0x20019
#define KEY_WRITE 0x20006

#define ACCESS KEY_WRITE
#undef ACCESS
#define ACCESS KEY_READ

LONG RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);

static LONG open_settings(HKEY root, PHKEY out)
{
    return RegOpenKeyExA(root, "SOFTWARE\\MyApp", 0, ACCESS, out);
}

void f(void)
{
    HKEY k;
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "S", 0, ACCESS, &k);
    open_settings(HKEY_LOCAL_MACHINE, &k);
}
