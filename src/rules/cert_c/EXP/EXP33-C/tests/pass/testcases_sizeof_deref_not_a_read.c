/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation.
 *
 * sizeof's operand is unevaluated per C11 6.5.3.4 -- `sizeof(*p)` computes
 * the pointee's size from p's static type without dereferencing p's actual
 * (here, not-yet-set) value, and `sizeof(arr[i])` never actually performs
 * the subscript access. check_reads visits the `*p` / `arr[i]` node
 * directly (not through check_identifier_read's is_read_context, which
 * already exempted plain `sizeof(x)`), so check_deref_read/
 * check_subscript_read need their own sizeof-ancestor exemption (task 391).
 * Real-world match: sqlite's `pRhs = sqlite3_malloc64(sizeof(*pRhs));` and
 * hostap's `while (left >= sizeof(*vhdr))` before vhdr is ever assigned.
 */

typedef struct Foo Foo;
void *malloc(unsigned long size);

Foo *makeFoo(void) {
    Foo *p;
    p = malloc(sizeof(*p));
    return p;
}

int sumSizeofElem(int *arr) {
    int i;
    return (int)sizeof(arr[i]);
}
