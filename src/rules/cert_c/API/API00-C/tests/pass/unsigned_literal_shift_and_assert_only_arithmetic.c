/*
 * Rule: API00-C
 * Source: custom
 * Status: PASS - Should NOT trigger API00-C violation
 * Description: Two integer-overflow FP classes from task 741.
 *
 * update_crc_64 (libcrc src/crc64.c): `crc << 8` on a uint64_t with a literal
 * shift count below the type's width. Unsigned wraparound is defined
 * behaviour and in a CRC it is the algorithm; the only undefined unsigned
 * shift is one whose count reaches the operand's width.
 *
 * bump (curl-shaped): the only arithmetic on the parameter is inside an
 * assert, which compiles out under NDEBUG and so is not a production
 * computation. Symmetric with guard_dominance's refusal to credit an assert
 * as validation -- an assert neither validates nor counts as a use.
 */

typedef unsigned long long uint64_t;
typedef unsigned int uint32_t;

void assert(int cond);
void DEBUGASSERT(int cond);

static const uint64_t crc_tab64[256];

uint64_t update_crc_64(uint64_t crc, unsigned char c)
{
    uint64_t t;

    t = (crc >> 56) ^ (uint64_t) c;
    return (crc << 8) ^ crc_tab64[t & 0xFF];
}

uint32_t rotate_left(uint32_t word)
{
    word <<= 3;
    return word;
}

int bump(int num)
{
    DEBUGASSERT(num + 1 > 0);
    assert(num * 2 != 0);
    return 0;
}
