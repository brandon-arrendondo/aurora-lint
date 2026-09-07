/*
 * Rule: MSC12-C
 * Status: PASS - two textually identical `&&` operands that each advance the
 *         pointer, so the second evaluation reads a different byte. sqlite's
 *         getVarint32() chains these deliberately.
 */

int varint_len(const unsigned char *p)
{
    const unsigned char *pIter = p;
    if ((*pIter++) & 0x80
     && (*pIter++) & 0x80) {
        return 2;
    }
    return 1;
}
