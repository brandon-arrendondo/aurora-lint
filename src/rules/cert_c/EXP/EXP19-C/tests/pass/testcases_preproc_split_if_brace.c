/*
 * Rule: EXP19-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP19-C violation
 */

/*
 * Rule: EXP19-C - Use braces for the body of an if, for, or while statement
 * Status: PASS
 * Reason: A preprocessor guard falling between the `if` header and its
 *         opening brace does not make the body unbraced. In every
 *         configuration that compiles, this is well-formed: with the guard's
 *         condition false the `if` is absent and the block is a plain
 *         compound statement; with it true the `if` governs that same braced
 *         block.
 *
 *         Only the unpreprocessed text is broken. `preproc_if` is a block
 *         item in tree-sitter-c, so the brace block parses as a SIBLING of
 *         the `if` and GLR recovery hands the `if` a synthesized
 *         `(expression_statement (MISSING ";"))` consequence -- which reads
 *         as an unbraced body. src/analyze/control_header_preproc_guard.rs
 *         blanks the directive lines pre-parse so the header rejoins the
 *         body it governs.
 *
 *         Distilled from sqlite src/wherecode.c, sqlite3WhereExplainOneScan
 *         and sqlite3WhereExplainBloomFilter.
 */

int check_a(int x);
int check_b(int x);

int explain_one_scan(int n)
{
    int ret = 0;

#if !defined(NDEBUG)
    if (check_a(n) || check_b(n))
#endif
    {
        ret = n;
    }

    return ret;
}

int scan_loop(int n)
{
    int i;
    int total = 0;

#ifdef FEATURE_LOOP
    for (i = 0; i < n; i++)
#endif
    {
        total += n;
    }

    return total;
}

int main(void)
{
    return explain_one_scan(1) + scan_loop(2);
}
