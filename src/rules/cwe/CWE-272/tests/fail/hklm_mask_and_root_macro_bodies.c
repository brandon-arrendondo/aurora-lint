/*
 * Rule: CWE-272
 * Status: FAIL - write masks and the root key behind object-like macros
 *         whose replacement is parenthesized or OR-combined, directly and in
 *         a wrapper body
 */

typedef void *HKEY;
typedef unsigned long DWORD;
typedef DWORD REGSAM;
typedef long LONG;
typedef const char *LPCSTR;
typedef HKEY *PHKEY;

#define HKEY_LOCAL_MACHINE ((HKEY)(unsigned long)0x80000002)
#define KEY_READ 0x20019
#define KEY_SET_VALUE 0x0002
#define PAREN_MASK (KEY_SET_VALUE)
#define OR_MASK (KEY_READ | KEY_SET_VALUE)
#define BARE_OR_MASK KEY_READ | KEY_SET_VALUE
#define READ_MASK (KEY_READ)
#define ROOT (HKEY_LOCAL_MACHINE)

LONG RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);

static LONG open_settings(HKEY root, PHKEY out)
{
    return RegOpenKeyExA(root, "SOFTWARE\\MyApp", 0, OR_MASK, out);
}

void f(void)
{
    HKEY k;
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "S", 0, PAREN_MASK, &k);    /* VIOLATION */
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "S", 0, OR_MASK, &k);       /* VIOLATION */
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "S", 0, BARE_OR_MASK, &k);  /* VIOLATION */
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "S", 0, READ_MASK, &k);     /* Compliant: a read */
    RegOpenKeyExA(ROOT, "S", 0, PAREN_MASK, &k);                  /* VIOLATION: macro root */
    RegOpenKeyExA((HKEY)(HKEY_LOCAL_MACHINE), "S", 0, PAREN_MASK, &k);  /* VIOLATION */
    open_settings(HKEY_LOCAL_MACHINE, &k);                        /* VIOLATION: wrapper */
}
