/*
 * Rule: STR11-C
 * Source: testcases
 * Status: FAIL - Should trigger STR11-C violation
 *
 * A typedef may name a structure tag before the structure is defined; the
 * later definition in the same scope completes that type (C11 6.7.2.3).
 * Both initializers fill a four-element member exactly, with no room for
 * the terminator: at file scope, and in a block after a bodiless
 * `struct S;` declaration.
 */
typedef struct S TS;
struct S {
    char name[4];
};
TS x = {"abcd"};

void f(void) {
    struct B;
    typedef struct B TB;
    struct B {
        char a[4];
    };
    TB v = {"abcd"};
    (void) v;
}
