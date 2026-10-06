/*
 * Rule: MEM33-C
 * Description: Pointer arithmetic over two flexible structs' sizes, the second written through its tag alone; the finding names the sizeof written first
 * Status: FAIL - Should trigger MEM33-C violation
 */

#include <stddef.h>

struct mid_entry {
    size_t len;
    char text[];
};

typedef struct big_entry {
    size_t len;
    char text[];
} big_entry;

struct mid_entry *after_pair(void *base) {
    return (struct mid_entry *)((char *)base + sizeof(struct mid_entry) * 2 + sizeof(big_entry));
}
