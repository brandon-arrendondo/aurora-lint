/*
 * Rule: ARR02-C
 * Source: testcases
 * Status: FAIL - Should trigger ARR02-C violation
 */

#include <stdio.h>

int main() {
    int implicit_array[] = {1, 2, 3, 4, 5};
    char text[] = "implicit sizing";
    double values[] = {1.1, 2.2, 3.3};
    
    printf("Array with implicit bounds\n");
    return 0;
}
