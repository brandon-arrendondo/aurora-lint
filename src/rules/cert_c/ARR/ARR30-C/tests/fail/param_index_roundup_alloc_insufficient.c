/*
 * Rule: ARR30-C
 * Status: FAIL - Should trigger ARR30-C violation
 */

/*
 * Reason: the allocation LOOKS like task 446's round-up-to-a-multiple safe
 * idiom, but the padding subtracted at the end is too large -- the
 * inequality (K1 + D*(C-1) + K_OUTER >= K2) does NOT hold here, so the
 * allocated size can be smaller than `dataSize`. Resolving the round-up
 * shape must still catch an insufficient guard, not accept any
 * div/mul/subtract shape unconditionally.
 */

void *RL_CALLOC(unsigned long count, unsigned long size);

unsigned int *ComputeBad(const unsigned char *data, int dataSize)
{
    static unsigned int hash[4] = { 0 };

    int newDataSize = (((dataSize + 8) / 64) * 64) - 100;

    unsigned char *msg = (unsigned char *)RL_CALLOC(newDataSize, 1);
    msg[dataSize] = 128;

    return hash;
}
