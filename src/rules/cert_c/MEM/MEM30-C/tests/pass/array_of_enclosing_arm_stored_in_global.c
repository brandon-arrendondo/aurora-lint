/*
 * Rule: MEM30-C
 * Source: synthetic
 * Status: PASS - The array is a file-scope object of the arm the function is in
 *
 * `g` is declared inside the `#ifdef`, outside any function, so it has
 * static storage duration. Storing its address in a global leaves nothing
 * pointing at a dead stack frame.
 */

int *gp;

#ifdef USE_TABLE

int g[4];

void select_table(void)
{
    gp = g;
}

#endif
