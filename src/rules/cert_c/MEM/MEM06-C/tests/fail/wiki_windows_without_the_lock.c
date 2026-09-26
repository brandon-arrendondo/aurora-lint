/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: CERT's Windows compliant solution with VirtualLock removed: VirtualAlloc'd memory is pageable until locked (the fail twin of wiki_windows.c).
 */
#include <windows.h>
#include <dpapi.h>
void protect_secret(SIZE_T size) {
  char *secret = (char *)VirtualAlloc(0, size + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (!secret) return;
  CryptProtectMemory(secret, CRYPTPROTECTMEMORY_BLOCK_SIZE, CRYPTPROTECTMEMORY_SAME_PROCESS);
  VirtualFree(secret, 0, MEM_RELEASE);
}
