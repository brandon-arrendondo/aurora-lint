/*
 * Rule: CWE-272
 * Status: FAIL - HKEY_LOCAL_MACHINE routed through a one-hop wrapper's
 *         parameter into RegCreateKeyExA, which creates the key: a write
 */

typedef void *HKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;
typedef HKEY *PHKEY;

#define HKEY_LOCAL_MACHINE ((HKEY)(unsigned long)0x80000002)
#define HKEY_CURRENT_USER ((HKEY)(unsigned long)0x80000001)
#define ERROR_SUCCESS 0L
#define KEY_WRITE 0x20006

LONG RegCreateKeyExA(HKEY, LPCSTR, DWORD, char *, DWORD, DWORD, void *, PHKEY, DWORD *);
LONG RegCloseKey(HKEY);

static int SaveSetting(HKEY Root, LPCSTR SubKey)
{
    HKEY hKey;
    if (RegCreateKeyExA(Root, SubKey, 0, 0, 0, KEY_WRITE, 0, &hKey, 0) != ERROR_SUCCESS)
        return 1;
    RegCloseKey(hKey);
    return 0;
}

int save_all(void)
{
    if (SaveSetting(HKEY_CURRENT_USER, "Software\\MyApp") != 0)  /* Compliant: HKCU */
        return 1;
    return SaveSetting(HKEY_LOCAL_MACHINE,  /* VIOLATION */
                       "Software\\MyApp");
}
