/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: sqlite mptest.c's runScript, task 1440. Two sibling blocks
 * each declare their own `char *zSql`, allocate into it and release it.
 * This rule's state is keyed by NAME with no scope attached, so the second
 * block's declaration inherited the first block's freed mark and its
 * release read as a double free.
 *
 * Nothing cleared the mark because only three initializer shapes were
 * handled -- a recognised allocator, an identifier, a NULL -- and
 * `sqlite3_mprintf` is none of them. A declaration introduces a new object
 * whatever it is initialized from, so every fact held about the previous
 * one stops applying to the name.
 *
 * Surfaced by task 1367, which made `sqlite3_free` a name-shaped
 * deallocator; the weakness itself pre-dates it and reproduces with any
 * such deallocator that has no summary.
 */

char *str_printf(const char *fmt, ...);
void obj_free(void *p);
void run_sql(const char *s);

void run_script(int n)
{
    int ii;

    for (ii = 0; ii < n; ii++) {
        char *zSql = str_printf("%d", ii);
        run_sql(zSql);
        obj_free(zSql);
    }

    if (n > 0) {
        char *zSql = str_printf("%d", n);
        run_sql(zSql);
        obj_free(zSql);
    }
}
