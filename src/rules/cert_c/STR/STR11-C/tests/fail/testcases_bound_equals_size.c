/*
 * Rule: STR11-C
 * Source: testcases
 * Status: FAIL - Should trigger STR11-C violation
 *
 * CERT's title forbids any bound on a character array initialized with a
 * string literal, so a bound exactly the literal's size (terminator
 * included) is reported too. Only a larger bound is excepted (EX2).
 */
const char s[4] = "abc";
char t[2] = "abc";  /* too short: a constraint violation */
