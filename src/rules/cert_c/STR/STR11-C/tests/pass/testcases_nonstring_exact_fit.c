/*
 * Rule: STR11-C
 * Source: testcases
 * Status: PASS - Should NOT trigger STR11-C violation
 *
 * EX1: an exact fit for an array declared nonstring, an intent GCC and
 * Clang check (they warn when such an array reaches a string function).
 */
[[gnu::nonstring]] char tag[4] = "abcd";
__attribute__((nonstring)) char id[3] = "XYZ";

struct record {
    __attribute__((nonstring)) char kind[4];
    int size;
};
struct record r = {"RIFF", 0};
