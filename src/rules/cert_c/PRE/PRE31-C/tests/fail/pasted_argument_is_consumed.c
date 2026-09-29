/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: FAIL - Should trigger PRE31-C violation
 *
 * The paste takes the argument's first token: `ID(counter++)` becomes
 * `id_counter++`, which increments a different object and never `counter`.
 * An argument evaluated zero times is as unsafe as one evaluated twice.
 */

int id_counter;

#define ID(x) id_ ## x

int next_id(void)
{
    static int counter;
    return ID(counter++);  /* VIOLATION: counter is never incremented */
}
