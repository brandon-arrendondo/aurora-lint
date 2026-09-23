/*
 * Rule: DCL18-C
 * Source: custom
 * Status: FAIL - Should trigger DCL18-C violation
 * Description: the message states an octal constant's decimal value, and
 * an integer suffix is not part of that value. `017L` is 15; parsing the
 * suffix along with the digits failed, and the failure was reported as
 * "evaluates to 0". A literal whose digits are not octal (`09`) has no
 * value to state.
 *
 * The generated fixture test only sees that DCL18-C fires; the value on
 * each line tagged VALUE is asserted by tests/cli_integration.rs.
 */

long a = 017L;      /* VALUE 15 */
unsigned b = 0755U; /* VALUE 493 */
unsigned long c = 010UL; /* VALUE 8 */
long long d = 0777LL; /* VALUE 511 */
int e = 017;        /* VALUE 15 */
int f = 09;         /* VALUE none */
