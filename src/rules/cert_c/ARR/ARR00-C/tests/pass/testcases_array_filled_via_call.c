/*
 * Rule: ARR00-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR00-C violation (task 195)
 * Description: An array filled by a function call (macro or plain function)
 * that receives it as a bare argument is not "uninitialized" even though
 * check_uninitialized_array_read's write-pattern scan only recognizes
 * `arr[i] = ...` subscript assignment -- see fill_array()/read() shape.
 */

#include <stdio.h>

void fill_array(int *arr, int n);

int main() {
    int arr[10];
    fill_array(arr, 10);

    for (int i = 0; i < 10; i++) {
        printf("%d ", arr[i]);
    }

    return 0;
}
