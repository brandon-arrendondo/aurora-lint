/*
 * Rule: DCL05-C
 * Source: real-world (ventoy Ventoy2Disk.c ParseCmdLineOption(LPSTR),
 *         Utility.c LPBYTE, WinDialog.c PTSTR; task 1188)
 * Status: PASS - Should NOT trigger DCL05-C violation
 *
 * Using a pointer typedef the Win32 API defines is not, by itself, what the
 * wiki calls noncompliant: its Windows example is `const LPPOINT pt`, the
 * const being the defect. A bare LPSTR parameter is the API's convention,
 * not the caller's typedef. Nor is a `P`-prefixed name evidence of a
 * pointer: PHY_DRIVE_INFO is a struct, LPARAM and ULONG_PTR are integers.
 */

/* LPSTR and LPBYTE come from <windows.h>, which is not on the include path;
 * the rule knows them as pointer typedefs from its Win32 table. */
typedef long LPARAM;
typedef unsigned long ULONG_PTR;
typedef struct PHY_DRIVE_INFO { int index; } PHY_DRIVE_INFO;

int ParseCmdLineOption(LPSTR lpCmdLine);

int copy_bytes(LPBYTE dest, unsigned long dest_size, const PHY_DRIVE_INFO *info,
               LPARAM lp, ULONG_PTR up)
{
    (void)dest;
    (void)dest_size;
    (void)info;
    (void)lp;
    return (int)up;
}

/* const on a pointer TO the alias qualifies the pointee, so nothing is hidden. */
void walk(const LPSTR *names, int n)
{
    (void)names;
    (void)n;
}
