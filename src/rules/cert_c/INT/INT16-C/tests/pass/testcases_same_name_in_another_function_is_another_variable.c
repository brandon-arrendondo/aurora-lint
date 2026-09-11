/*
 * Rule: INT16-C
 * Source: custom
 * Status: PASS - should NOT trigger INT16-C violation
 * Description: A name declared signed in one function says nothing about
 * the same name declared unsigned in another. lua's ltable.c `findindex`
 * returns its own `unsigned int i` from an `unsigned int` function and was
 * reported as "signed variable returned as unsigned" because an unrelated
 * `int i` elsewhere in the file had put the NAME in a file-wide signed map.
 * Every question here is answered by the declaration in scope at the use:
 * the return, the bitwise ops and the assignment below all involve an
 * unsigned `i`, and the shadowing block-scope `i` is unsigned too.
 */

int count_slots(int n) {
    int i;
    int total = 0;
    for (i = 0; i < n; i++) {
        total += i;
    }
    return total;
}

unsigned int findindex(unsigned int size, unsigned int key) {
    unsigned int i = key % size;
    unsigned int mask = i & 0x7u;
    unsigned int high = i >> 3;
    unsigned int dest;
    dest = i;
    (void)mask;
    (void)high;
    (void)dest;
    return i;
}

unsigned int shadowed(int outer) {
    {
        unsigned int outer = 4u;
        unsigned int low = outer & 1u;
        (void)low;
        return outer;
    }
}
