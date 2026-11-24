/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - A typedef defines only its own name, not the types its parameters mention
 * Expect: count=2
 *
 * `SetDefaultDllDirectories_t` and `Query_t` are pointers to `WINAPI`
 * functions taking a `DWORD` and a `ULONG`. They define no `DWORD` or
 * `ULONG` of their own, so nothing in reach defines either name, and each is
 * the Windows SDK's unsigned 32-bit type. Converting one to `int` changes a
 * value above `INT_MAX`.
 */

typedef int BOOL;
typedef BOOL(WINAPI *SetDefaultDllDirectories_t)(DWORD);
typedef BOOL (WINAPI *Query_t)(ULONG, DWORD);

int count(DWORD Value)
{
    return (int)Value; /* Expect: here */
}

int length(ULONG Value)
{
    return (int)Value; /* Expect: here */
}
