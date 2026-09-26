/*
 * Rule: ARR30-C
 * Source: testcases
 * Status: FAIL - Should trigger ARR30-C violation
 */

/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: FAIL
 * Reason: A static function indexes an array with an enum-typed parameter and
 * checks nothing. A C enum does not constrain the values its type holds (any
 * value of the underlying integer type converts to it), and a static function
 * says nothing about what its callers pass unless every call site is seen to
 * pass a valid index -- here nothing calls it at all.
 */

typedef enum { LED_RED, LED_GREEN, LED_BLUE } led_id_t;

static void set_led(int *brightness, led_id_t id, int level)
{
    brightness[id] = level;
}
