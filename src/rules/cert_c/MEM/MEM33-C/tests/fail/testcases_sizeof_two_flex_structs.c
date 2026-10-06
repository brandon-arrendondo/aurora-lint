/*
 * Rule: MEM33-C
 * Description: Pointer arithmetic over two flexible structs' sizes; the finding names the sizeof written first
 * Status: FAIL - Should trigger MEM33-C violation
 */

#include <stddef.h>

struct zrecord {
    size_t num;
    int data[];
};

struct arecord {
    size_t num;
    int data[];
};

struct arecord *second_record(void *base) {
    return (struct arecord *)((char *)base + sizeof(struct zrecord) + sizeof(struct arecord));
}
