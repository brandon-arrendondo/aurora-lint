/*
 * Rule: MEM30-C
 * Source: real-world (hostap: the traced os_realloc copies into a fresh
 *         block and frees the old one only once the copy succeeded;
 *         os_realloc_array over it; the parse loop frees the old array when
 *         growing fails)
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Description: `grow` returns NULL before it releases anything when it
 * cannot get a new block, so the caller still owns `list` on that branch
 * and frees it once. A release that an earlier `return` can skip is not
 * made on every path.
 */
#include <stdlib.h>
#include <string.h>

void *mem_alloc(size_t size)
{
    return malloc(size);
}

void mem_release(void *ptr)
{
    free(ptr);
}

void *grow(void *ptr, size_t old_size, size_t size)
{
    void *fresh;

    if (ptr == NULL)
        return mem_alloc(size);
    fresh = mem_alloc(size);
    if (fresh == NULL)
        return NULL;
    memcpy(fresh, ptr, old_size < size ? old_size : size);
    mem_release(ptr);
    return fresh;
}

static inline void *grow_array(void *ptr, size_t count, size_t size)
{
    if (size && count > ((size_t) -1) / size)
        return NULL;
    return grow(ptr, (count - 1) * size, count * size);
}

int collect(const int *values, size_t n, int **out)
{
    int *list = NULL, *bigger;
    size_t count = 0;

    for (size_t i = 0; i < n; i++) {
        bigger = grow_array(list, count + 1, sizeof(int));
        if (bigger == NULL) {
            mem_release(list);
            return -1;
        }
        list = bigger;
        list[count++] = values[i];
    }
    *out = list;
    return 0;
}
