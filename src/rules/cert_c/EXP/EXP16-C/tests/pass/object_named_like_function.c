/*
 * Rule: EXP16-C
 * Source: aurora-lint
 * Status: PASS - every tested name is an object, not a function
 *
 * The file declares a function count(), but the local count in tally() is an
 * int. The parameter rand is an int, not the library function. A function
 * pointer object compared to 0 is an ordinary null test. `x == 2;` discards
 * a comparison, which is not a function compared to a constant.
 */
int count(void);

int tally(int n) {
    int count = n;
    if (count)
        return 1;
    return 0;
}

int seeded(int rand) {
    return rand == 0;
}

int dispatch(void (*cb)(void), int x) {
    x == 2;
    if (cb)
        cb();
    return cb != 0;
}
