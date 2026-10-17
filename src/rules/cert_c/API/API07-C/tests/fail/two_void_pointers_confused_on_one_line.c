/*
 * Rule: API07-C
 * Status: FAIL - Type confusion via void pointer
 *
 * Both pointers on the one line are dereferenced as a wider type than the
 * object they point to.
 */

long both(void) {
    char c = 'A';
    short s = 42;
    void *narrow = &c;
    void *wide = &s;
    long sum = *((long *)wide) + *((long *)narrow);
    return sum;
}
