/*
 * Rule: FLP38-C
 * Source: wiki
 * Status: FAIL - Should trigger FLP38-C violation
 */

_Float32 f = 2.0;
long double d = 3.0;
double result = nexttoward(f, d);   // Undefined Behavior
printf("result is %lf\n", result);