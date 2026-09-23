/*
 * Rule: WIN05-C
 * Status: PASS - the same wrapper fed HKEY_CURRENT_USER: following the
 *         handle through the wrapper must not turn every caller into a
 *         finding, only the ones that hand it HKLM/HKCR
 */

typedef void *HKEY;
typedef unsigned long DWORD;
typedef long LONG;
typedef const char *LPCSTR;
typedef HKEY *PHKEY;

#define HKEY_CURRENT_USER ((HKEY)(unsigned long)0x80000001)
#define REGKEY_HKCU HKEY_CURRENT_USER
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

int user_setting(void)
{
    DWORD Value = 0;
    if (GetRegDwordValue(HKEY_CURRENT_USER,  /* Compliant: HKCU */
                         "Software\\MyApp", "Setting", &Value) == 0)
        return (int)Value;
    if (GetRegDwordValue(REGKEY_HKCU,  /* Compliant: alias of HKCU */
                         "Software\\MyApp", "Other", &Value) == 0)
        return (int)Value;
    return 0;
}
