/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP33-C violation
 */

/*
 * CERT C EXP33-C Fail Case: function_parameter_issues.c
 *
 * This case demonstrates violations involving function parameters
 * and return values with uninitialized memory.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* NON-COMPLIANT: Function doesn't initialize output parameter in all paths */
int get_user_input(int *value) {
    char input[100];

    if (fgets(input, sizeof(input), stdin) == NULL) {
        return -1;  /* value remains uninitialized */
    }

    if (strlen(input) == 0) {
        return -1;  /* value remains uninitialized */
    }

    *value = atoi(input);
    return 0;
}

void test_uninitialized_output(void) {
    int user_value;  /* Uninitialized */

    /* Function may not initialize user_value */
    if (get_user_input(&user_value) != 0) {
        printf("Input failed\n");
    }

    /* Reading potentially uninitialized value */
    printf("User value: %d\n", user_value);  /* Undefined behavior if function failed */
}

/* NON-COMPLIANT: Passing uninitialized parameters to functions */
void process_coordinates(int x, int y, int z) {
    printf("Processing point (%d, %d, %d)\n", x, y, z);

    double distance = sqrt(x*x + y*y + z*z);
    printf("Distance from origin: %.2f\n", distance);
}

void test_uninitialized_parameters(void) {
    int x, y, z;  /* All uninitialized */

    /* Only initialize some parameters */
    x = 10;
    /* y and z remain uninitialized */

    process_coordinates(x, y, z);  /* Passing uninitialized y, z */
}

/* Not a violation: static storage is zero-initialized (C11 6.7.9p10), so
 * these reads are determinate. Kept as a guard against reporting them. */
static int global_counter;
static int global_sum;

void unsafe_accumulator(int value) {
    global_counter++;
    global_sum += value;

    printf("Count: %d, Sum: %d\n", global_counter, global_sum);
}

/* NON-COMPLIANT: Function returns uninitialized value */
int calculate_result(int a, int b, int operation) {
    int result;  /* Uninitialized */

    switch (operation) {
        case 1:
            result = a + b;
            break;
        case 2:
            result = a - b;
            break;
        case 3:
            result = a * b;
            break;
        /* Missing default case or case 0 */
    }

    return result;  /* Returns uninitialized value for unsupported operations */
}

/* NON-COMPLIANT: Callback function receives uninitialized data */
void process_item(int item, void (*callback)(int)) {
    if (callback != NULL) {
        callback(item);
    }
}

void callback_function(int value) {
    printf("Callback received: %d\n", value);
}

void test_callback_with_uninitialized(void) {
    int data;  /* Uninitialized */

    /* Passing uninitialized data to function that uses callback */
    process_item(data, callback_function);  /* Undefined behavior */
}

/* NON-COMPLIANT: Variadic function with uninitialized arguments */
void print_numbers(int count, ...) {
    va_list args;
    va_start(args, count);

    for (int i = 0; i < count; i++) {
        int num = va_arg(args, int);
        printf("Number %d: %d\n", i + 1, num);
    }

    va_end(args);
}

void test_variadic_uninitialized(void) {
    int a = 1, b, c;  /* b and c uninitialized */

    print_numbers(3, a, b, c);  /* Passing uninitialized b, c */
}

int main(void) {
    printf("=== Function Parameter Issues Demo ===\n");

    printf("1. Uninitialized output parameter:\n");
    test_uninitialized_output();

    printf("\n2. Uninitialized function parameters:\n");
    test_uninitialized_parameters();

    printf("\n3. Uninitialized return value:\n");
    int result = calculate_result(5, 3, 0);  /* Unsupported operation */
    printf("Result: %d\n", result);  /* Undefined behavior */

    printf("\n4. Callback with uninitialized data:\n");
    test_callback_with_uninitialized();

    printf("\n5. Variadic function with uninitialized args:\n");
    test_variadic_uninitialized();

    return 0;
}