/*
 * Rule: INT30-C
 * Source: real-world (seL4 `pde_t *CONST lookupPDSlot(pde_t *pd, vptr_t vptr)`
 *         read as an expression inside a damaged region)
 * Status: PASS - Should NOT trigger INT30-C violation
 * Reason: Only a function-like macro can take a type as an argument, so a
 *         type name in a FUNCTION's argument list is a parameter declaration
 *         the parser misread, not a value of that unsigned type. And a `*`
 *         whose left operand names a type is a pointer declarator, never a
 *         product.
 */

typedef unsigned long word_t;
typedef word_t vptr_t;
typedef struct pde { word_t words[1]; } pde_t;

int lookup(int a, int b);

int declarations_read_as_products(int n, int pd, unsigned int upd)
{
    int r;
    r = n * lookup(n * pd, vptr_t vptr);
    r = word_t * (vptr_t)pd;
    r = word_t * upd;
    return r;
}
