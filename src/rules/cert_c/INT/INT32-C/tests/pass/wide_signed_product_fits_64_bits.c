/*
 * Rule: INT32-C
 * Source: task 1323 (valkey src/sds.h:127, src/rdb.c:330)
 * Status: PASS - the `ll` suffix and the `(long long)` cast make this
 *         64-bit arithmetic, and neither shape comes near INT64_MAX.
 *
 * `1ll << 32` does not fit in an `int`, which is precisely why valkey
 * writes the suffix, and `(long long)1 << 31` is the idiom for naming the
 * 32-bit range in a 64-bit type. The rule checked every signed operation
 * against a 32-bit limit regardless of its operands -- PROMOTED_ARITH_BITS,
 * whose own doc scopes it to "int-wide or NARROWER" -- so the very cast
 * that makes the code correct was what made it look wrong.
 */

#include <stddef.h>

static size_t max_size_for(char type)
{
    if (type == 5) {
        return (1ll << 32) - 1;
    }
    return 0;
}

int in_int32_range(long long value)
{
    return value >= -((long long) 1 << 31) && value <= ((long long) 1 << 31) - 1;
}

size_t use_max_size(char type)
{
    return max_size_for(type);
}
