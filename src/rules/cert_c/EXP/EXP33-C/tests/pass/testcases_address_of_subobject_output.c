/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation. An address taken inside
 * a variable's own storage -- `&s.field`, `&a[i]`, `&(x)`, `&s.inner.v` -- is
 * somewhere for the callee to write, not a content read, and a callee that
 * writes through it initializes the variable. Both halves used to understand
 * only `&ident`, so hostap's `recvfrom(..., &from.ss, &fromlen)` reported
 * `from` uninitialized at the very call that fills it (task 1028).
 */
#include <stdio.h>

struct inner {
    int v;
};

struct outer {
    int len;
    struct inner in;
    int arr[4];
};

extern void fill_int(int *p);
extern void fill_bytes(unsigned char *p, int n);

void use_int(int v);

/* &var.field */
void field_output(void) {
    struct outer s;
    fill_int(&s.len);
    use_int(s.len);
}

/* &var.field.field */
void nested_field_output(void) {
    struct outer s;
    fill_int(&s.in.v);
    use_int(s.in.v);
}

/* &var[i] */
void element_output(void) {
    int a[4];
    fill_int(&a[0]);
    use_int(a[0]);
}

/* &(var) */
void parenthesized_output(void) {
    int x;
    fill_int(&(x));
    use_int(x);
}

/* A cast over the address-of, as curl and hostap both spell it. */
void cast_output(void) {
    struct outer s;
    fill_bytes((unsigned char *)&s.arr[0], (int)sizeof(s.arr));
    use_int(s.arr[0]);
}

/* &var[i] at a scanf-family output position (task 1029's funnel reaching
   task 1028's argument shape -- hostap's
   `sscanf(authsrv, "%d.%d.%d.%d", &a[0], &a[1], &a[2], &a[3])`). */
void scanf_element_output(const char *s) {
    int a[4];
    sscanf(s, "%d.%d.%d.%d", &a[0], &a[1], &a[2], &a[3]);
    use_int(a[0]);
}
