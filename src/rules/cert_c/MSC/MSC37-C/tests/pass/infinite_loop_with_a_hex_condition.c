/*
 * Rule: MSC37-C
 * Source: synthetic
 * Status: PASS - a loop whose condition is a nonzero constant in any radix never ends
 */

int next(void);

int find(int target)
{
    while (0x1) {
        int value = next();
        if (value == target) {
            return value;
        }
    }
}
