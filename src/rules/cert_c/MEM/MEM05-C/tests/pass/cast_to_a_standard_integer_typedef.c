/*
 * Rule: MEM05-C
 * Source: synthetic
 * Status: PASS - A cast of a constant to a standard integer typedef
 *
 * `size_t` and `uint32_t` are integer types, so a cast of a constant to
 * one keeps an array size constant (C11 6.6p6).
 */
#include <stddef.h>
#include <stdint.h>

void sink(char *p);

void fixed_sizes(void)
{
    char by_size[(size_t)8];
    char by_width[(uint32_t)4 * 2];
    sink(by_size);
    sink(by_width);
}
