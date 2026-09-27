/*
 * Rule: INT33-C
 * Source: regression
 * Status: FAIL - `10 / p->d` divides by an int field without a zero check
 *
 * The field's struct comes from the base identifier's type. An inner block
 * declares its own `struct scale *p`, whose `d` is a double, and the
 * function-wide name map used to answer for the outer `p`, so the divisor
 * read as floating-point. The outer `p` points to `struct count`, whose `d`
 * is an int.
 */

struct count { int d; };
struct scale { double d; };

int per_item(struct count *q) {
    struct count *p = q;
    int r = 10 / p->d;
    {
        struct scale *p = 0;
        (void)p;
    }
    return r;
}
