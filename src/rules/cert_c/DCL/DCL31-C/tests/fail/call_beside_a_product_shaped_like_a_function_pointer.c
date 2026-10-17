/*
 * Rule: DCL31-C
 * Status: FAIL - Should trigger DCL31-C violation
 */

/*
 * Reason: `pick(width * probe)(1);` is a product inside a call of a call,
 * not a declaration: `width` is a variable, not a calling convention. So
 * `probe` is still undeclared where it is called.
 */

typedef int (*picker)(int);
picker pick(int);

int run(int width)
{
    pick(width * probe)(1);
    return probe(width); /* VIOLATION */
}
