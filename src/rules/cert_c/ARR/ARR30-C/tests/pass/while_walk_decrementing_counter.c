/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: PASS
 * Reason: A counter that decreases by one every iteration bounds the walk as
 *         surely as a size comparison does -- the loop cannot run more times
 *         than the counter's initial value. Both places the idiom is written
 *         count: the decrement inside the condition, and an unconditional
 *         decrement at the top level of the body.
 */

void copy_postfix_condition(unsigned char *dst, const unsigned char *src, unsigned n) {
    while (n--) {
        *dst++ = *src++;
    }
}

void copy_prefix_condition(unsigned char *dst, const unsigned char *src, unsigned left) {
    while (--left != 0) {
        *dst++ = *src++;
    }
}

void fill_body_decrement(unsigned char *rnd, unsigned num, unsigned char r) {
    while (num) {
        *rnd++ = r;
        num--;
    }
}

void accumulate_body_predecrement(const unsigned char *pos, unsigned left, unsigned *out) {
    unsigned value = 0;
    while (left) {
        value <<= 8;
        value |= *pos++;
        --left;
    }
    *out = value;
}
