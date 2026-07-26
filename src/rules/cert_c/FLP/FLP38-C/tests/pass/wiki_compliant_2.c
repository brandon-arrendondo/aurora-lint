/*
 * Rule: FLP38-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

_Float32 f = 2.0;
long double d = 3.0;
double result = nexttoward((double) f, d);
printf("result is %lf\n", result);