/*
 * Rule: ARR30-C
 * Status: PASS - Should NOT trigger ARR30-C violation
 */

/*
 * Reason: `buffer[dataSize]` is provably in-bounds because `buffer` is
 * allocated to a size derived from `dataSize` via the SHA-256 hash-padding
 * "round up to a multiple of 64" idiom -- expressed as a mod-based two-
 * statement computation (`paddedSize = dataSize + K; paddedSize += (64 -
 * paddedSize % 64);`) rather than `match_roundup_formula`'s single-
 * expression div-mul shape (task 448). The added term is always in
 * `[1, 64]`, so `paddedSize` is always strictly greater than `dataSize`.
 * Also covers `RL_CALLOC(count, sizeof(unsigned char))` being recognized
 * as an element-size-1 allocation, same as a literal `1`.
 */

void *RL_CALLOC(unsigned long count, unsigned long size);

unsigned int *ComputeSHA256(const unsigned char *data, int dataSize)
{
    static unsigned int hash[8] = { 0 };

    unsigned long long paddedSize = dataSize + sizeof(dataSize);
    paddedSize += (64 - (paddedSize % 64));

    unsigned char *buffer = (unsigned char *)RL_CALLOC(paddedSize, sizeof(unsigned char));
    buffer[dataSize] = 0x80;

    return hash;
}

unsigned int *ComputeSHA256SelfAssign(const unsigned char *data, int dataSize)
{
    static unsigned int hash[8] = { 0 };

    unsigned long long paddedSize = dataSize + 8;
    paddedSize = paddedSize + (64 - (paddedSize % 64));

    unsigned char *buffer = (unsigned char *)RL_CALLOC(paddedSize, 1);
    buffer[dataSize] = 0x80;

    return hash;
}
