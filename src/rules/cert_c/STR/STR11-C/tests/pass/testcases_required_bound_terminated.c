/*
 * Rule: STR11-C
 * Source: testcases
 * Status: PASS - Should NOT trigger STR11-C violation
 *
 * Where C requires the bound - an inner dimension of an array of strings,
 * a structure member, a typedef'd array - it cannot be left out, so a
 * bound that holds the literal with its terminator is compliant. Only the
 * unterminated cases are reported there.
 */
const char table[][4] = {"abc", "de", "f"};

struct name {
    char text[4];
};
struct name n = {"abc"};

typedef char code_t[3];
code_t c = "ab";
