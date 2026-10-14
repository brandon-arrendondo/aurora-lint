/*
 * Rule: DCL30-C
 * Status: FAIL - Should trigger DCL30-C violation
 * Reason: A continue that skips the reset reaches the loop's exit with the
 *         address still stored, and a reset in a sibling #else arm belongs
 *         to another build, not to the path holding the store.
 */

int *g;

int check(void);
void use(void);

void continue_skips_the_reset(int n)
{
    int x = 0;
    while (n--) {
        for (int i = 0; i < n; i++)
            g = &x;             /* VIOLATION */
        if (check())
            continue;
        g = 0;
    }
}

void reset_in_the_other_arm(void)
{
    int x = 0;
#ifdef FEATURE
    g = &x;                     /* VIOLATION */
    use();
#else
    g = 0;
#endif
}
