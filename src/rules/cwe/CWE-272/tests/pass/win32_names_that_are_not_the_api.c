/*
 * Rule: CWE-272
 * Status: PASS - a Win32 registry name that is not the Win32 API: the
 *         project's own function of that name (called directly and through a
 *         wrapper), a function-pointer parameter and a local of that name
 *         (declared through the LONG typedef, a declaration tree-sitter
 *         reads as a call), and a macro that replaces it
 */

typedef void *HKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;
typedef const unsigned char *LPCBYTE;

#define HKEY_LOCAL_MACHINE ((HKEY)(unsigned long)0x80000002)
#define REG_DWORD 4

LONG trace_reg(HKEY, LPCSTR, DWORD, DWORD, LPCBYTE, DWORD);
#define RegSetValueExA trace_reg

/* The project's own function, not advapi32's. */
LONG RegDeleteValueA(HKEY key, const char *name)
{
    (void)key;
    (void)name;
    return 0;
}

static LONG wipe(HKEY root)
{
    return RegDeleteValueA(root, "v");
}

typedef LONG (*create_fn)(HKEY, LPCSTR, HKEY *);

void f(create_fn RegCreateKeyA)
{
    HKEY out;
    DWORD one = 1;
    LONG (*RegDeleteKeyA)(HKEY, LPCSTR) = 0;

    RegDeleteValueA(HKEY_LOCAL_MACHINE, "v");                   /* Compliant: own function */
    wipe(HKEY_LOCAL_MACHINE);                                   /* Compliant: through it */
    RegCreateKeyA(HKEY_LOCAL_MACHINE, "Software\\MyApp", &out); /* Compliant: a parameter */
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, "Software\\MyApp");       /* Compliant: a local */
    RegSetValueExA(HKEY_LOCAL_MACHINE, "Setting", 0, REG_DWORD, /* Compliant: a macro */
                   (LPCBYTE)&one, sizeof one);
}
