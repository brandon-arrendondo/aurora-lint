/*
 * Rule: MEM05-C
 * Source: synthetic
 * Status: PASS - Each size is a constant reached through macros, sizeof or offsetof
 *
 * A function-like macro is what its replacement list is with its
 * arguments in place, so `cast_int(sizeof(t) * 8)` over a type is a
 * constant. `sizeof` of a macro for a string literal, of a standard
 * typedef, and `offsetof` of a struct are constants too (C11 6.6, 7.19).
 * An array at file scope or a struct member cannot be variable-length at
 * all, so its size is never reported, whatever this file can show of it.
 */
#include <stddef.h>

#define cast(t, exp) ((t)(exp))
#define cast_int(i) cast(int, (i))
#define numbits(t) cast_int(sizeof(t) * 8)
#define PREFIX ""
#define SUFFIX ".tmp"
#define NAME_LENGTH (sizeof(PREFIX) - 1 + 16 + sizeof(SUFFIX))

struct item { int n; int a[1]; };

void sink(void *p);

static int table[HEADER_COUNT];

struct holder {
    char buf[HEADER_LENGTH];
};

void fixed_sizes(void)
{
    unsigned char bits[(numbits(long) + 6) / 7];
    char name[NAME_LENGTH];
    char by_standard_type[sizeof(size_t) * 2];
    char head[offsetof(struct item, a) + sizeof(int)];
    sink(bits);
    sink(name);
    sink(by_standard_type);
    sink(head);
    sink(table);
}
