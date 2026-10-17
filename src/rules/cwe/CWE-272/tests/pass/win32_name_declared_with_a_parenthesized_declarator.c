/*
 * Rule: CWE-272
 * Status: PASS - a Win32 registry name declared through a function-pointer
 *         typedef with a parenthesized declarator, `reg_delete_fn
 *         (RegDeleteKeyA) = 0;`, is that pointer, not the Win32 API:
 *         tree-sitter reads the declaration as an assignment to a call of
 *         the typedef, which a type cannot be
 */

typedef void *HKEY;
typedef long LONG;
typedef const char *LPCSTR;

#define HKEY_LOCAL_MACHINE ((HKEY)(unsigned long)0x80000002)

typedef LONG (*reg_delete_fn)(HKEY, LPCSTR);

reg_delete_fn (RegDeleteValueA) = 0;

void f(void)
{
    reg_delete_fn (RegDeleteKeyA) = 0;

    RegDeleteKeyA(HKEY_LOCAL_MACHINE, "Software\\MyApp");      /* Compliant: a pointer */
    RegDeleteValueA(HKEY_LOCAL_MACHINE, "Setting");            /* Compliant: a pointer */
}
