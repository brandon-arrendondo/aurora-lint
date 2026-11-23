/*
 * Rule: MEM05-C
 * Source: synthetic
 * Status: FAIL - A cast to a standard integer typedef of a runtime value
 * Expect: count=2
 *
 * A cast to an integer type keeps what its operand is: one that reads a
 * parameter is no constant, so each array is variable-length.
 */
#include <stddef.h>
#include <stdint.h>

void sink(char *p);

void runtime_sizes(int n)
{
    char by_size[(size_t)n];
    char by_width[(uint8_t)n + 1];
    sink(by_size);
    sink(by_width);
}
