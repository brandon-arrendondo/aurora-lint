/*
 * Rule: DCL37-C
 * Status: PASS - a function defined with an ordinary name; its parameter
 * `_x` has block scope, where an underscore followed by a lowercase letter is
 * not reserved.
 */

int scale(int _x) { return _x * 2; }
