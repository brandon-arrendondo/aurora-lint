/*
 * Rule: DCL06-C
 * Source: synthetic
 * Status: PASS - a value from 0 to 10 is accepted whatever its suffix
 * Description: A float constant's f/F/l/L and an integer constant's u/U/l/L
 *   are suffixes, so 1.0f, 2.0F and 10UL are 1, 2 and 10. Only in a
 *   hexadecimal constant is f a digit.
 */

float scale(float x) {
    return x * 1.0f + 2.0F;
}

unsigned long clamp(unsigned long n) {
    if (n > 10UL) {
        return 10UL;
    }
    return n;
}

int low_nibble(int x) {
    return x & 0x0aU;
}

double offset(double d) {
    return d - 1.0L;
}
