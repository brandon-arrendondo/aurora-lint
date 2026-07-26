/*
 * Rule: FLP38-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

double d = 3.0;
_Decimal64 d64 = 2.0;
double result = remainder((double) d64, d);
printf("result is %lf\n", result);