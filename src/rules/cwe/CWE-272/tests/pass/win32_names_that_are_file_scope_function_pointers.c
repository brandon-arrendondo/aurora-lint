/*
 * Rule: CWE-272
 * Status: PASS - a Win32 registry name declared at file scope as a function
 *         pointer is that object, not the Win32 API, whether the declaration
 *         spells the pointer out (tree-sitter reads `LONG (*f)(...)` as a
 *         call), names it through a function-pointer typedef, or has an
 *         empty parameter list
 */

typedef void *HKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;
typedef const unsigned char *LPCBYTE;
typedef HKEY *PHKEY;

#define HKEY_LOCAL_MACHINE ((HKEY)(unsigned long)0x80000002)
#define KEY_WRITE 0x20006
#define REG_DWORD 4

/* Spelled out: every parameter type a typedef. */
LONG (*RegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPCSTR, DWORD, DWORD, void *, PHKEY, DWORD *);
/* Through a typedef of the pointer type. */
typedef LONG (*set_value_fn)(HKEY, LPCSTR, DWORD, DWORD, LPCBYTE, DWORD);
static set_value_fn RegSetValueExA;
/* No parameter list to tell it from a call. */
LONG (*RegDeleteKeyA)();
/* Initialized. */
static LONG (*RegOpenKeyExA)(HKEY, LPCSTR, DWORD, DWORD, PHKEY) = 0;

void f(void)
{
    HKEY key;
    DWORD one = 1;

    RegCreateKeyExA(HKEY_LOCAL_MACHINE, "Software\\MyApp", 0, 0, 0, KEY_WRITE, 0, &key, 0); /* Compliant: a pointer */
    RegSetValueExA(HKEY_LOCAL_MACHINE, "Setting", 0, REG_DWORD, (LPCBYTE)&one, sizeof one); /* Compliant: a pointer */
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, "Software\\MyApp");      /* Compliant: a pointer */
    RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\MyApp", 0, KEY_WRITE, &key); /* Compliant: a pointer */
}
