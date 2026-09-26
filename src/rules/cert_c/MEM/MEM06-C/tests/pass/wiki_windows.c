/*
 * Rule: MEM06-C
 * Source: wiki
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: CERT's Windows compliant solution: VirtualAlloc'd, VirtualLock'd before the secret (handed to CryptProtectMemory) is used.
 */

#include <windows.h>
#include <dpapi.h>

void protect_secret(SIZE_T size) {
  char *secret;

  secret = (char *)VirtualAlloc(0, size + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (!secret) {
    return;
  }

  if (!VirtualLock(secret, size+1)) {
      return;
  }

  /* Perform operations using secret... */
  CryptProtectMemory(secret, CRYPTPROTECTMEMORY_BLOCK_SIZE, CRYPTPROTECTMEMORY_SAME_PROCESS);

  SecureZeroMemory(secret, size + 1);
  VirtualUnlock(secret, size + 1);
  VirtualFree(secret, 0, MEM_RELEASE);
  secret = NULL;
}
