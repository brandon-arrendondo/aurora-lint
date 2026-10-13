/*
 * Rule: CWE-272
 * Status: FAIL - a mask macro redefined to a write before the call, and a
 *         root key or mask cast inside a second pair of parentheses, as
 *         written and behind a macro, directly and in a wrapper body
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
#define MYROOT ((HKEY)HKEY_LOCAL_MACHINE)
#define MYMASK ((REGSAM)KEY_WRITE)
#define ROOT_CHAIN MYROOT

#define ACCESS KEY_READ
#undef ACCESS
#define ACCESS KEY_WRITE

LONG RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);

static LONG open_settings(HKEY root, PHKEY out)
{
    return RegOpenKeyExA(root, "SOFTWARE\\MyApp", 0, ((REGSAM)KEY_WRITE), out);
}

void f(void)
{
    HKEY k;
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "S", 0, ACCESS, &k);              /* VIOLATION */
    RegOpenKeyExA(((HKEY)HKEY_LOCAL_MACHINE), "S", 0, KEY_WRITE, &k);   /* VIOLATION */
    RegOpenKeyExA(MYROOT, "S", 0, KEY_WRITE, &k);                       /* VIOLATION */
    RegOpenKeyExA(ROOT_CHAIN, "S", 0, KEY_WRITE, &k);                   /* VIOLATION */
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "S", 0, ((REGSAM)KEY_WRITE), &k); /* VIOLATION */
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "S", 0, MYMASK, &k);              /* VIOLATION */
    open_settings(((HKEY)HKEY_LOCAL_MACHINE), &k);                      /* VIOLATION: wrapper */
}
