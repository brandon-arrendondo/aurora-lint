/*
 * Rule: ARR30-C
 * Source: wiki
 * Status: FAIL - Should trigger ARR30-C violation
 */

error_status_t _RemoteActivation(
      handle_t hRpc, WCHAR *pwszObjectName) {
   HRESULT *phr;
   *phr = GetServerPath(
              pwszObjectName, &pwszObjectName);
    /* ... */
}

HRESULT GetServerPath(
  WCHAR *pwszPath, WCHAR **pwszServerPath ){
  WCHAR *pwszFinalPath = pwszPath;
  WCHAR wszMachineName[MAX_COMPUTERNAME_LENGTH_FQDN+1];
  hr = GetMachineName(pwszPath, wszMachineName);
  *pwszServerPath = pwszFinalPath;
}

HRESULT GetMachineName(
  WCHAR *pwszPath,
  WCHAR wszMachineName[MAX_COMPUTERNAME_LENGTH_FQDN+1])
{
  pwszServerName = wszMachineName;
  LPWSTR pwszTemp = pwszPath + 2;
  while (*pwszTemp != L'\\')
    *pwszServerName++ = *pwszTemp++;
  /* ... */
}