/*
 * Rule: FLP06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FLP06-C violation
 */

/*
 * FLP06-C PASS Case: float initializers that are NOT integer arithmetic.
 *
 * Regression guard for the residual raylib FP sub-classes (task 237) that the
 * old text `contains('+-*/')` heuristic misfired on. The rule now drives off
 * the AST and fires only on a top-level +,-,*,/ binary expression whose
 * operands are all provably integer — so none of these fire.
 */

extern float sinf(float);
extern float cosf(float);

struct V2 { float x; float y; };

/* float-returning calls — the '->' / 'f' in names must not read as arithmetic */
float trig(float a, float b)
{
    float ring = sinf(a)*cosf(b);
    return ring;
}

/* arithmetic is in the subscript INDEX; the read value is the element */
float byte_read(const unsigned char *data, int w, int x, int y)
{
    float f1 = data[(y*w + x)*4];
    return f1;
}

/* unary minus on a single literal — not binary arithmetic */
float unary_literal(void)
{
    float pixelValue = -1;
    return pixelValue;
}

/* struct-field operands (unknown type without project context) — not provably integer */
float field_math(struct V2 v, struct V2 t)
{
    float value = (t.x - v.x)*(t.x - v.x) + (t.y - v.y)*(t.y - v.y);
    return value;
}
