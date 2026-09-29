/*
 * Rule: INT34-C
 * Status: PASS - For loop variable bounded by condition < 32
 * Settings: data_model=lp64
 *
 * The bounds are 32 because the target is declared LP64, where unsigned
 * int is 32 bits; ISO C guarantees it only 16.
 */


unsigned int f(unsigned int val) {
    unsigned int result = 0;
    for (int i = 0; i < 32; i++) {
        result |= (val >> i) & 1;
    }
    return result;
}

unsigned int g(unsigned int val) {
    unsigned int result = 0;
    for (int bit = 0; bit <= 31; bit++) {
        if ((val >> bit) & 1u) {
            result++;
        }
    }
    return result;
}
