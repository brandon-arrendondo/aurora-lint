/*
 * Rule: MEM30-C
 * Source: aurora-lint
 * Status: PASS - an unknown calling-convention macro sends the parse of this
 * function-pointer typedef into recovery, which leaves it reading as
 * `typedef union u { ... } v, DWORD`. `DWORD` is the next parameter's type,
 * not a name for the union, so `d` is no union whose members share storage:
 * freeing `d.a` frees nothing that `d.b` points to.
 */

#include <stdlib.h>

typedef LONG (WINAPI * PFN_Pick)(HKEY hKey, union u { int *a; int *b; } v, DWORD count);

int read_after(void) {
    DWORD d;
    d.a = malloc(sizeof(int));
    d.b = malloc(sizeof(int));
    free(d.a);
    return *d.b;
}
