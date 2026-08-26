/*
 * Rule: ARR02-C
 * Source: testcases
 * Status: FAIL - Should trigger ARR02-C violation
 */

#include <stdio.h>

int main() {
    int matrix[][5] = {
        {1, 2, 3, 4, 5},
        {6, 7, 8, 9, 10},
        {11, 12, 13, 14, 15}
    };

    char grid[][10] = {
        "Hello",
        "World",
        "Test"
    };

    double tensor[][3][4] = {
        {{1.0, 2.0}, {3.0, 4.0}},
        {{5.0, 6.0}, {7.0, 8.0}}
    };

    printf("Multidimensional arrays with missing first dimension\n");

    return 0;
}