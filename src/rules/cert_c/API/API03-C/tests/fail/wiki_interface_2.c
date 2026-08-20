/*
 * Rule: API03-C
 * Source: wiki
 * Status: FAIL - Should trigger API03-C violation
 */

#include <stdio.h>
#define fputs(X,Y) fputs(Y,X)
