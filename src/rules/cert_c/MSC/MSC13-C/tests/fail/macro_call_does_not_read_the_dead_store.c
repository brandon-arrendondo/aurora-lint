/*
 * Rule: MSC13-C
 * Status: FAIL - crediting a macro call with reading the free identifiers in
 * its body must not credit it with reading everything in scope. LOG_Y()
 * reads `y`, not `x`, so `x = 1` is still a genuine dead store (task 756).
 */

void use(int);

#define LOG_Y() use(y)

void f(void)
{
    int y = 7;
    int x = 1;    /* VIOLATION: dead — LOG_Y() reads y, never x */
    LOG_Y();
    x = 2;
    use(x);
}
