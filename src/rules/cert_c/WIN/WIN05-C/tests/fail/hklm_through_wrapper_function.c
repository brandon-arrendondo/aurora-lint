/*
 * Rule: WIN05-C
 * Status: FAIL - HKEY_LOCAL_MACHINE routed into RegOpenKeyExA through a
 *         one-hop wrapper's parameter (ventoy's GetRegDwordValue, task 1167)
 */

typedef void *HKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;
typedef HKEY *PHKEY;

#define HKEY_LOCAL_MACHINE ((HKEY)(unsigned long)0x80000002)
#define ERROR_SUCCESS 0L
#define KEY_QUERY_VALUE 0x0001

LONG RegOpenKeyExA(HKEY, LPCSTR, DWORD, DWORD, PHKEY);
LONG RegCloseKey(HKEY);

int GetRegDwordValue(HKEY Key, LPCSTR SubKey, LPCSTR ValueName, DWORD *pValue)
{
    HKEY hKey;
    LONG lRet = RegOpenKeyExA(Key, SubKey, 0, KEY_QUERY_VALUE, &hKey);
    if (ERROR_SUCCESS == lRet) {
        *pValue = 1;
        RegCloseKey(hKey);
        return 0;
    }
    return 1;
}

int count_disks(void)
{
    DWORD Value = 0;
    if (GetRegDwordValue(HKEY_LOCAL_MACHINE,  /* VIOLATION */
                         "SYSTEM\\CurrentControlSet\\Services\\disk\\Enum",
                         "Count", &Value) == 0)
        return (int)Value;
    return 0;
}
