/*
 * Rule: INT30-C
 * Source: real-world (raylib GenMeshPlane `texcoords[u + v*resX]`)
 * Status: PASS - Should NOT trigger INT30-C violation
 * Reason: Every operand here is declared `int`, so each sum and product is
 *         signed arithmetic (INT32-C's concern), not an unsigned wrap. An
 *         operand's type comes from its declaration, not from its spelling:
 *         a variable named `u` (or `iMul`) is not a literal with a `u` (or
 *         `ul`) suffix, and a name containing `size_t`, `uint` or
 *         `unsigned` is not that type.
 */

struct grid {
    int mu;
    int buf_size_total;
};

void plane_texcoords(float *texcoords, int resX, int resZ)
{
    for (int v = 0; v < resZ; v++)
    {
        for (int u = 0; u < resX; u++)
        {
            texcoords[u + v*resX] = 0.0f;
        }
    }
}

int names_that_look_unsigned(int lu, int count_uints, int is_unsigned, int buf_size_t)
{
    int a = lu * 3;
    int b = count_uints + is_unsigned;
    return a + b + buf_size_t * 2;
}

int field_named_like_a_literal(struct grid *g, int n)
{
    return g->mu * n + g->buf_size_total;
}

long long reverse_delta(long long iDocid, long long iDelta, int bDescIdx)
{
    int iMul = (bDescIdx ? -1 : 1);
    iDocid += (iMul * iDelta);
    return iDocid;
}
