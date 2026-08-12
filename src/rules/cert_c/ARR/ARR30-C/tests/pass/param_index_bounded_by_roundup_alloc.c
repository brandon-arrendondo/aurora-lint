/*
 * Rule: ARR30-C
 * Status: PASS - Should NOT trigger ARR30-C violation
 */

/*
 * Reason: `msg[dataSize]` is provably in-bounds because `msg` is allocated
 * to a size derived from `dataSize` via the classic MD5/SHA1 hash-padding
 * "round up to a multiple of 64" idiom -- the allocated size is always
 * strictly greater than `dataSize` by construction (task 446). Covers both
 * the direct-subterm case (`calloc(dataSize + K, ...)`) and the one-level
 * variable-indirection case (allocate from a local variable that was itself
 * computed as a round-up of `dataSize`).
 */

void *RL_CALLOC(unsigned long count, unsigned long size);

unsigned int *ComputeMD5(const unsigned char *data, int dataSize)
{
    static unsigned int hash[4] = { 0 };

    int newDataSize = ((((dataSize + 8) / 64) + 1) * 64) - 8;

    unsigned char *msg = (unsigned char *)RL_CALLOC(newDataSize + 64, 1);
    msg[dataSize] = 128;

    return hash;
}

unsigned int *ComputeSHA1(const unsigned char *data, int dataSize)
{
    static unsigned int hash[5] = { 0 };

    int newDataSize = ((((dataSize + 8) / 64) + 1) * 64);

    unsigned char *msg = (unsigned char *)RL_CALLOC(newDataSize, 1);
    msg[dataSize] = 128;

    return hash;
}

unsigned int *DirectSubterm(const unsigned char *data, int dataSize)
{
    static unsigned int hash[4] = { 0 };

    unsigned char *msg = (unsigned char *)RL_CALLOC(dataSize + 9, 1);
    msg[dataSize] = 128;

    return hash;
}
