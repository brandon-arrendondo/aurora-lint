/*
 * Rule: ARR30-C
 * Source: testcases
 * Status: FAIL - Should trigger ARR30-C violation
 *
 * The index is a chain of definitions, each naming the one written after
 * it, that comes to 16, one past the end of a 16-element array. Each round
 * of constant resolution settles one link of a chain written in this
 * order, so the index is known only if the rounds run until nothing
 * changes rather than stopping at a fixed count.
 */

#define SLOT (SLOT_1 + 1)
#define SLOT_1 (SLOT_2 + 1)
#define SLOT_2 (SLOT_3 + 1)
#define SLOT_3 (SLOT_4 + 1)
#define SLOT_4 (SLOT_5 + 1)
#define SLOT_5 (SLOT_6 + 1)
#define SLOT_6 10

void fill(void)
{
    char table[16];
    table[SLOT] = 0; /* index 16 */
}
