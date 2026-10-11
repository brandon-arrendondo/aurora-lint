/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - The guard and the division share one line
 */

int divide(int a, int d) { if (d == 0) return 0; return a / d; }
