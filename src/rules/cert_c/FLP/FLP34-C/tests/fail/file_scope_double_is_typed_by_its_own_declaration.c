/*
 * Rule: FLP34-C
 * Source: regression
 * Status: FAIL - `out = reading` converts the file-scope double to float
 * without a range check
 *
 * The function-local name maps never record a file-scope variable, so
 * `reading` used to go untyped here -- or, with a map built from the whole
 * file, be typed by another function's `float reading`. The occurrence's
 * own declaration is the file-scope double.
 */

double reading = 1e300;

float narrow_reading(void) {
    float out;
    out = reading;
    return out;
}

void unrelated(void) {
    float reading = 0.0f;
    (void)reading;
}
