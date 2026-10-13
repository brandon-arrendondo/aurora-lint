/*
 * Rule: CWE-272
 * Status: FAIL - a root key and a write mask behind casts, and a wrapper
 *         whose open spells its write mask through an alias
 */

typedef void *HKEY;
typedef unsigned long DWORD;
typedef DWORD REGSAM;
typedef long LONG;
typedef const char *LPCSTR;
typedef HKEY *PHKEY;

#define HKEY_LOCAL_MACHINE ((HKEY)(unsigned long)0x80000002)
#define KEY_WRITE 0x20006
#define APP_ACCESS KEY_WRITE

LONG RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);

static LONG open_for_update(HKEY root, PHKEY out)
{
    return RegOpenKeyExA(root, "SOFTWARE\\MyApp", 0, APP_ACCESS, out);
}

void f(void)
{
    HKEY key;
    RegOpenKeyExA((HKEY)HKEY_LOCAL_MACHINE,  /* VIOLATION: cast root key */
                  "SOFTWARE", 0, KEY_WRITE, &key);
    RegOpenKeyExA(HKEY_LOCAL_MACHINE,  /* VIOLATION: cast mask */
                  "SOFTWARE", 0, (REGSAM)KEY_WRITE, &key);
    RegOpenKeyExA(HKEY_LOCAL_MACHINE,  /* VIOLATION: cast parenthesized mask */
                  "SOFTWARE", 0, (REGSAM)(KEY_WRITE), &key);
    open_for_update(HKEY_LOCAL_MACHINE,  /* VIOLATION: alias mask in the wrapper */
                    &key);
}
