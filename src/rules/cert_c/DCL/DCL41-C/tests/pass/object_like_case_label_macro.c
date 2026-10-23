/*
 * Rule: DCL41-C
 * Source: testcases
 * Status: PASS - Should NOT trigger DCL41-C violation
 *
 * CASE_VOWEL and OTHERWISE are object-like macros whose every definition
 * begins with a case or default label, written with no `;`. tree-sitter
 * glues each to the statement after it and reads the pair as a declaration
 * of the macro's type, but the expansion is a label followed by that
 * statement: nothing precedes the first case label.
 */

int classify(int kind);

#define CASE_VOWEL case 'a': case 'e': case 'i': case 'o': case 'u':
#define OTHERWISE default:

int vowel(int c) {
  switch (c) {
    CASE_VOWEL classify(1);
      return 1;
    OTHERWISE
      return 0;
  }
}
