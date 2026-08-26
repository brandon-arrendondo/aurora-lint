/*
 * Rule: ARR02-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR02-C violation (brace initializer determines the bound; well-defined per C11 6.7.9p22, task 567)
 */

#include <stdio.h>

int main() {
    int numbers[] = {1, 2, 3, 4, 5};
    double values[] = {1.1, 2.2, 3.3};
    char text[] = "implicit sizing";
    
    printf("Arrays with implicit bounds\n");
    return 0;
}
