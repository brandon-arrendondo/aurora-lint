/*
 * Rule: ARR30-C
 * Status: PASS - Should NOT trigger ARR30-C violation
 */

/*
 * Reason: the ordinary buffer-plus-its-own-length calling convention, walked
 * backwards (pureftpd's puredbw_hash, task 911). `len` is the length of
 * `msg`, and every `msg[len]` read is dominated by the `while (len != 0)`
 * loop condition it is decremented under, so the index range is
 * [0, original len - 1]. The guard is a `while` rather than an `if`, which
 * is the only reason it read as unvalidated.
 */

unsigned long hash_backwards(const char *const msg, unsigned long len)
{
    unsigned long j = 5381UL;

    while (len != 0) {
        len--;
        j += (j << 5);
        j ^= ((unsigned char)msg[len]);
    }

    return j;
}
