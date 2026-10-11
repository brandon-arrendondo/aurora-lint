/*
 * Rule: STR11-C
 * Source: testcases
 * Status: FAIL - Should trigger STR11-C violation
 *
 * Inside a block, `struct S *p` and `sizeof(struct S)` refer to the visible
 * file-scope S; they declare nothing (C11 6.7.2.3p9). The later `struct S x`
 * therefore has the file-scope members, and its four-element member is
 * filled exactly, with no room for the terminator.
 */
struct S {
    char a[4];
};

void pointer_first(void) {
    struct S *p = 0;
    struct S x = {"abcd"};
    (void) p;
    (void) x;
}

void sizeof_first(void) {
    unsigned long n = sizeof(struct S);
    struct S x = {"abcd"};
    (void) n;
    (void) x;
}
