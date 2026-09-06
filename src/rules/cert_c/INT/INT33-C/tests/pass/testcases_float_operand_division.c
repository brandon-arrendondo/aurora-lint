/*
 * Rule: INT33-C
 * Source: raylib-audit (task 228)
 * Status: PASS - Not an INT33-C violation
 * Reason: INT33-C is the INTEGER divide-by-zero rule. Division where either
 *         operand is float-typed is floating-point division (well-defined
 *         inf/nan on a zero divisor), so none of these should be flagged.
 *         Mirrors the raymath.h idioms that produced 388 false positives.
 */

typedef struct Vector2 {
    float x;
    float y;
} Vector2;

/* typedef alias of a struct whose fields are float */
typedef Vector2 Point2;

/* float params, float binary-expression divisor: (end - start) */
float remap(float value, float start, float end) {
    return (value - start) / (end - start);
}

/* float local divisor */
float scale(float v, float factor) {
    float divisor = factor;
    return v / divisor;
}

/* float struct-field divisor (resolved via prescan struct field types) */
float divide_components(Vector2 a, Vector2 b) {
    return a.x / b.x;
}

/* float divisor reached through a typedef alias */
float divide_alias(Point2 a, Point2 b) {
    return a.y / b.y;
}

/* dividend cast to double makes the whole division floating-point */
double avg(int sum, int count) {
    return (double)sum / count;
}

/* float literal dividend */
float half_of(float x) {
    return 180.0f / x;
}
