/**
 * Compliant patterns: writing to struct/union fields or subscript+field does NOT
 * constitute a read of the base variable, so should NOT trigger EXP33-C.
 */

#include <stdio.h>
#include <stdlib.h>

typedef struct { int a; int b; } Pair;
typedef union { short u16; int u32; } Conv;

/* Pattern 1: direct field write on stack struct */
void test_struct_field_write(void)
{
    Pair p;
    p.a = 1;   /* write to field — base 'p' not read */
    p.b = 2;
    printf("%d %d\n", p.a, p.b);
}

/* Pattern 2: union field write (Juliet CWE190 pattern) */
void test_union_field_write(short x)
{
    Conv c;
    c.u16 = x;  /* write — 'c' not read */
    printf("%d\n", c.u32);
}

/* Pattern 3: malloc'd array subscript+field write */
void test_malloc_subscript_field_write(void)
{
    Pair *arr = (Pair *)malloc(4 * sizeof(Pair));
    if (arr == NULL) return;
    arr[0].a = 0;  /* write through subscript+field — arr[0] is not read */
    arr[0].b = 0;
    free(arr);
}

typedef union { char a[8]; int i; } ByteBuf;

/* Pattern 4: field+subscript write (sqlite's util.c sqlite3Int64ToText
 * pattern) — the base 'u' is not read just because one element of its
 * array member is being written through. */
void test_field_subscript_write(int idx)
{
    ByteBuf u;
    int i = idx;
    u.a[i] = 0;   /* write through field+subscript — 'u' is not read */
    printf("%d\n", u.i);
}
