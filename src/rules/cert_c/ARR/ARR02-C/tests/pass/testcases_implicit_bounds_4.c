/*
 * Rule: ARR02-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR02-C violation (brace initializer determines the bound; well-defined per C11 6.7.9p22, task 567)
 */

#include <stdio.h>

int main() {
    int implicit_array[] = {1, 2, 3, 4, 5};
    char text[] = "implicit sizing";
    double values[] = {1.1, 2.2, 3.3};
    
    printf("Array with implicit bounds\n");
    return 0;
}
