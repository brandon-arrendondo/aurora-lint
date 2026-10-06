/*
 * Rule: ARR30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR30-C violation
 *
 * The index is a chain of definitions, each naming the one written after
 * it, that comes to 15, the last element of a 16-element array. Each round
 * of constant resolution settles one link of a chain written in this
 * order; stopping the rounds at a fixed count left the index unknown and
 * the access reported as unsafe.
 */

#define SLOT (SLOT_1 + 1)
#define SLOT_1 (SLOT_2 + 1)
#define SLOT_2 (SLOT_3 + 1)
#define SLOT_3 (SLOT_4 + 1)
#define SLOT_4 (SLOT_5 + 1)
#define SLOT_5 (SLOT_6 + 1)
#define SLOT_6 9

void fill(void)
{
    char table[16];
    table[SLOT] = 0; /* index 15 */
}
