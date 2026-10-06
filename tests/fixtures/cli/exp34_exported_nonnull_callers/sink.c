/* `get` has external linkage; its only call site passes the address of an
 * object. Whether that proves `q` non-null depends on whether the scanned
 * files are all of its callers (closed_program, ADR-0011). */
struct s { int a; };

int get(struct s *q)
{
    int v = q->a;
    if (q == 0)
        return -1;
    return v;
}
