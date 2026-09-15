/*
 * Rule: WIN03-C
 * Source: custom
 * Status: FAIL - Should trigger WIN03-C violation
 * Description: OpenMutexW with bInheritHandle TRUE -- the wide entry point
 * the OpenMutex macro expands to under UNICODE. The rule matched the bare
 * macro name only (task 1130).
 */

#include <windows.h>

HANDLE open_shared(void) {
    return OpenMutexW(MUTEX_ALL_ACCESS, TRUE, L"Global\\VentoyMutex");
}
