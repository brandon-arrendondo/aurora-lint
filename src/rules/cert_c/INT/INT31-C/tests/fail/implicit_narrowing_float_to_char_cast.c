/*
 * Rule: INT31-C
 * Source: custom
 * Status: FAIL - Should trigger INT31-C violation
 * Description: Explicit cast narrowing an unguarded float parameter to
 * unsigned char, e.g. raylib's rlColor4f(float r, ...) { (unsigned char)(r*255) }.
 * Not FLP34-C's territory (that's float<->float precision loss); this is a
 * float value narrowed into an integer type with no local range check.
 */

unsigned char to_byte(float ratio) {
    return (unsigned char)(ratio * 255.0f);
}
