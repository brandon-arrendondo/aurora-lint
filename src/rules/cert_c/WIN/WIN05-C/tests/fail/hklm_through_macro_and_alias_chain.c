/*
 * Rule: WIN05-C
 * Status: FAIL - HKLM behind an object-like alias, routed through a
 *         function -> forwarding macro -> function chain into RegOpenKeyExA
 *         (ventoy's REGKEY_HKLM / ReadRegistryKey32 / GetRegistryKey32 /
 *         _GetRegistryKey)
 */

typedef void *HKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef int BOOL;
typedef int INT32;
typedef const char *LPCSTR;
typedef unsigned char *LPBYTE;
typedef HKEY *PHKEY;

#define HKEY_LOCAL_MACHINE ((HKEY)(unsigned long)0x80000002)
#define REGKEY_HKLM HKEY_LOCAL_MACHINE
#define ERROR_SUCCESS 0L
#define KEY_READ 0x20019
#define REG_DWORD 4
#define TRUE 1
#define FALSE 0

LONG RegOpenKeyExA(HKEY, LPCSTR, DWORD, DWORD, PHKEY);
LONG RegQueryValueExA(HKEY, LPCSTR, DWORD *, DWORD *, LPBYTE, DWORD *);
LONG RegCloseKey(HKEY);

static BOOL _GetRegistryKey(HKEY key_root, const char *key_name, DWORD reg_type,
                            LPBYTE dest, DWORD dest_size)
{
    HKEY hApp = 0;
    DWORD dwType = reg_type, dwSize = dest_size;
    if (RegOpenKeyExA(key_root, "SOFTWARE", 0, KEY_READ, &hApp) != ERROR_SUCCESS)
        return FALSE;
    RegQueryValueExA(hApp, key_name, 0, &dwType, dest, &dwSize);
    RegCloseKey(hApp);
    return TRUE;
}

#define GetRegistryKey32(root, key, pval) \
    _GetRegistryKey(root, key, REG_DWORD, (LPBYTE)pval, sizeof(DWORD))

static INT32 ReadRegistryKey32(HKEY root, const char *key)
{
    DWORD val = 0;
    GetRegistryKey32(root, key, &val);
    return (INT32)val;
}

int windows_ubr(void)
{
    return ReadRegistryKey32(REGKEY_HKLM,  /* VIOLATION */
                             "Software\\Microsoft\\Windows NT\\CurrentVersion\\UBR");
}
