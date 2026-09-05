// sqc-test: prescan
/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Safe wrapper for malloc with error checking
void* safe_malloc(size_t size) {
    if (size == 0) {
        return NULL;
    }

    void *ptr = malloc(size);
    if (!ptr) {
        printf("Memory allocation failed for size %zu\n", size);
    }

    return ptr;
}

// Safe wrapper for realloc
void* safe_realloc(void *ptr, size_t new_size) {
    if (new_size == 0) {
        free(ptr);
        return NULL;
    }

    void *new_ptr = realloc(ptr, new_size);
    if (!new_ptr) {
        printf("Memory reallocation failed for size %zu\n", new_size);
        // Original pointer is still valid
        return ptr;
    }

    return new_ptr;
}

// Safe free that sets pointer to NULL
void safe_free(void **ptr) {
    if (ptr && *ptr) {
        free(*ptr);
        *ptr = NULL;
    }
}

// Safe string duplication
char* safe_strdup(const char *str) {
    if (!str) {
        return NULL;
    }

    size_t len = strlen(str);
    char *copy = safe_malloc(len + 1);
    if (copy) {
        strcpy(copy, str);
    }

    return copy;
}

int main() {
    // Test safe allocation wrappers
    int *numbers = (int*)safe_malloc(10 * sizeof(int));
    if (numbers) {
        for (int i = 0; i < 10; i++) {
            numbers[i] = i * i;
        }

        printf("Allocated and initialized array\n");

        // Test safe realloc
        numbers = (int*)safe_realloc(numbers, 20 * sizeof(int));
        if (numbers) {
            for (int i = 10; i < 20; i++) {
                numbers[i] = i * i;
            }
            printf("Successfully reallocated array\n");
        }

        // Safe free - memory freed exactly once
        safe_free((void**)&numbers);
        printf("Array freed safely\n");

        // Safe to call again - does nothing
        safe_free((void**)&numbers);
    }

    // Test string operations
    char *original = "Hello, World!";
    char *copy = safe_strdup(original);
    if (copy) {
        printf("String copy: %s\n", copy);
        safe_free((void**)&copy);
        printf("String copy freed\n");
    }

    return 0;
}