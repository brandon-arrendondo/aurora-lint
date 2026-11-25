/*
 * Rule: ARR01-C
 * Source: aurora-lint
 * Status: PASS - an unknown calling-convention macro sends the parse of this
 * function-pointer typedef into recovery, which leaves it reading as
 * `typedef struct fx { ... } v, DWORD`. `DWORD` is the next parameter's type,
 * not a name for `struct fx`, so `x.d` is no flexible array member, and the
 * file's `struct fixed` declares a `d` that has a size.
 */

#include <string.h>

typedef LONG (WINAPI * PFN_Fill)(HKEY hKey, struct fx { int n; int d[]; } v, DWORD count);

struct fixed {
    int n;
    int d[8];
};

void clear(void) {
    DWORD x;
    memset(x.d, 0, sizeof(x.d));
}
