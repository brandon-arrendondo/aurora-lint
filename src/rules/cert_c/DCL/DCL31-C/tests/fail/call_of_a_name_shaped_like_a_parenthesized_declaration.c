/*
 * Rule: DCL31-C
 * Status: FAIL - Should trigger DCL31-C violation
 */

/*
 * Reason: `refresh (cache);` is a call of `refresh`, which nothing
 * declares: no typedef of that name is in scope here, since the one in
 * `setup` is local to that function, so the statement is not a
 * declaration of `cache`.
 */

int cache;

void setup(void)
{
    typedef int refresh;
    refresh (local) = 0;
    (void)local;
}

void run(void)
{
    refresh (cache); /* VIOLATION */
}
