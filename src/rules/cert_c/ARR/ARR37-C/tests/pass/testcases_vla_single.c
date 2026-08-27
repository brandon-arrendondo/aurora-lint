/*
 * Rule: ARR37-C
 * Source: testcases
 * Status: PASS - Should not trigger ARR37-C violation
 */

/*
 * Rule: ARR37-C - Do not add or subtract an integer to a pointer to a non-array object
 * Status: PASS
 * Reason: `&vla[0]` is a pointer into the VLA `vla`, not a pointer to a
 * standalone non-array object -- it's the same address `vla` itself decays
 * to. Pointer arithmetic on it is legitimate array-pointer arithmetic, the
 * same as arithmetic on `vla` directly. Whether `n` keeps the result in
 * bounds is an ARR30-C/ARR38-C concern, not an ARR37-C one.
 */

void vla_test(int n) {
    int vla[n];
    vla[0] = 100;

    // Get pointer to the VLA's first element (== vla itself)
    int *ptr = &vla[0];

    ptr += n;
    *ptr = 200;
}

int main(void) {
    vla_test(1);  // With n=1, ptr+n is definitely out of bounds
    return 0;
}
