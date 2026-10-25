/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: PASS - size parameters typed by a typedef of size_t
 *
 * lu_mem names size_t, and mem_len names lu_mem: each parameter named for
 * a size is a size_t by its declaration.
 */
#include <stddef.h>

typedef size_t lu_mem;
typedef lu_mem mem_len;

void *grow_block(void *block, lu_mem len, mem_len *newsize);
