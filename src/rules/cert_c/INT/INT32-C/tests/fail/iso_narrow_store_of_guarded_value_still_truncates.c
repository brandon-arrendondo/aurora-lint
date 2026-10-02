/*
 * Rule: INT32-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * A guard bounds one side of an operand's range, and for a result that stays
 * int-wide the open side is the type's own limit, so the guarded sum cannot
 * overflow. A result stored into a narrower type is the truncating-store
 * channel: the open end of an int or long operand is not the limit of the
 * short or signed char it is stored into, so the value can be out of range
 * there. For a signed char that holds on every implementation with 8-bit
 * chars; for a short it holds wherever int is wider than short, which every
 * declared model has and ISO C allows without guaranteeing, so a store into
 * a short is reported with and without a declared model.
 */

short to_short(int value) {
    if (value < 1) {
        return 0;
    }
    short result = value - 1; /* VIOLATION */
    return result;
}

signed char to_signed_char(int value) {
    if (value < 1) {
        return 0;
    }
    signed char result = value - 1; /* VIOLATION */
    return result;
}

signed char returned_as_signed_char(int value) {
    if (value < 1) {
        return 0;
    }
    return value - 1; /* VIOLATION */
}

short cast_to_short(int value) {
    if (value < 1) {
        return 0;
    }
    return (short)(value - 1); /* VIOLATION */
}

short long_to_short(long value) {
    if (value < 1) {
        return 0;
    }
    short result = value - 1; /* VIOLATION */
    return result;
}

signed char mirror_to_signed_char(int value) {
    if (value > 0) {
        return 0;
    }
    signed char result = value + 1; /* VIOLATION */
    return result;
}
