/*
 * Rule: ARR02-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR02-C violation
 */

/* Array-typed function parameters are adjusted to pointer type by C
 * (C11 6.7.6.3p7) -- not array OBJECT declarations, so an omitted bound
 * here is out of scope for ARR02-C (task 567). Covers both a prototype
 * declaration and a K&R-style old-style parameter declaration. */
void proto_with_array_param(int arr[]);

int krnr_style(arr)
    int arr[];
{
    return arr[0];
}

int main() {
    int values[] = {1, 2, 3};
    proto_with_array_param(values);
    return krnr_style(values);
}
