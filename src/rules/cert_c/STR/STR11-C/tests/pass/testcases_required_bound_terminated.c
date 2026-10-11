/*
 * Rule: STR11-C
 * Source: testcases
 * Status: PASS - Should NOT trigger STR11-C violation
 *
 * Where the declaration cannot leave the bound out - an inner dimension of
 * an array of strings or a structure member, which C requires, or a
 * typedef'd array, whose bound belongs to every use of the type - a bound
 * that holds the literal with its terminator is compliant. Only the
 * unterminated cases are reported there.
 */
const char table[][4] = {"abc", "de", "f"};

struct name {
    char text[4];
};
struct name n = {"abc"};

typedef char code_t[3];
code_t c = "ab";
