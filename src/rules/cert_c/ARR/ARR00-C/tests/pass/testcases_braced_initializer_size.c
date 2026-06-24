/*
 * Rule: ARR00-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR00-C violation
 */

/*
 * ARR00-C PASS Case: array bound resolved from the AST declaration
 *
 * Regression guard for the size-misparse FP class found in the raylib audit
 * (task 234). The old text heuristic latched onto subscript *uses* and failed
 * to recognize user-typed declarations, so it miscounted these arrays and
 * flagged every legitimate access as out of bounds. All accesses below are
 * in-bounds and must stay silent.
 */

#define SEGMENTS 24

typedef struct Vector2 {
    float x;
    float y;
} Vector2;

/* User-typed array with an explicit numeric size and a braced initializer.
   Index 11 is valid for point[12]. */
void braced_user_type(void)
{
    const Vector2 point[12] = {
        {0.0f, 0.0f}, {1.0f, 1.0f}, {2.0f, 2.0f}, {3.0f, 3.0f},
        {4.0f, 4.0f}, {5.0f, 5.0f}, {6.0f, 6.0f}, {7.0f, 7.0f},
        {8.0f, 8.0f}, {9.0f, 9.0f}, {10.0f, 10.0f}, {11.0f, 11.0f}
    };
    float sum = point[8].x + point[9].x + point[10].x + point[11].x;
    (void)sum;
}

/* Size given as a constant expression with a macro. 2*24 + 2 = 50,
   so indices 0 and 1 are well within bounds. */
void const_expr_size(void)
{
    Vector2 points[2 * SEGMENTS + 2] = { 0 };
    points[0].x = 1.0f;
    points[1].y = 2.0f;
}

/* Zero-initialized array: {0} is a single initializer element but the
   declared size is 6, so faceRecs[5] is valid. */
void zero_init_size(void)
{
    int faceRecs[6] = { 0 };
    faceRecs[5] = 1;
}

/* Block-scoped shadowing: a tmp[3] in one branch must not be used as the
   bound for the tmp[4] in another branch. tmp[3] is valid for float[4]. */
void scoped_shadow(int which)
{
    if (which == 0)
    {
        float tmp[3] = { 0.0f };
        tmp[2] = 1.0f;
    }
    else
    {
        float tmp[4] = { 0.0f };
        tmp[3] = 1.0f;
    }
}
