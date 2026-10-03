/*
 * Rule: INT32-C
 * Source: regression
 * Status: PASS - the model fixes int at 32 bits and unsigned short at 16
 * Settings: data_model=lp64
 *
 * An unsigned short promotes to int, so `i < u` is an int comparison and
 * keeps i below USHRT_MAX, well short of the limit of int.
 */

int use_index(int i);

int bounded_by_a_narrower_unsigned(int i, unsigned short u) {
    if (i < u) {
        return use_index(i + 1);
    }
    return 0;
}
