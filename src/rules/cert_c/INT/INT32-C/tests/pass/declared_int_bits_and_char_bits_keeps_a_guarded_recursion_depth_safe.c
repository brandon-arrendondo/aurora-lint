/*
 * Rule: INT32-C
 * Source: regression
 * Status: PASS - a width declared on its own settles the same proof as a data model
 * Settings: int_bits=32, char_bits=8
 *
 * A guard bounds the top of `depth`; its bottom is the type's own. Declaring
 * only some of the facts a data model would load must not leave the type's
 * range open, so `depth + 1` cannot overflow.
 */

void descend(int depth) {
    if (depth > 10) {
        return;
    }
    descend(depth + 1);
}
