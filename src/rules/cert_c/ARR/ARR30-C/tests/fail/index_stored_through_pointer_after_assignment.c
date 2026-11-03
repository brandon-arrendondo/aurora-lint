/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - The index's last assignment is not its value
 *
 * `i = 2` is the last assignment to `i` by name, but the store through `q`
 * after it replaces the value with an unchecked one.
 */

int read_untrusted(void);

int fill(void)
{
    int buf[10];
    int i;
    int *q = &i;
    i = 2;
    *q = read_untrusted();
    buf[i] = 1;
    return buf[0];
}
