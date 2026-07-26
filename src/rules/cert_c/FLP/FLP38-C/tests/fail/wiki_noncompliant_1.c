/*
 * Rule: FLP38-C
 * Source: wiki
 * Status: FAIL - Should trigger FLP38-C violation
 */

double d = 3.0;
_Decimal64 d64 = 2.0;
double result = remainder(d64, d);   // Undefined Behavior
printf("result is %fl\n", result);