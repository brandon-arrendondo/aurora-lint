/*
 * Rule: MSC13-C
 * Source: mbedtls library/ (task 1387; bmdb 1214's 91 rows)
 * Status: FAIL - Should trigger MSC13-C violation
 *
 * `int ret = ERR_CORRUPTION_DETECTED;` is written as fault-injection
 * hardening, but every path from the declaration overwrites `ret` before
 * any read: the CHK macro's `ret = (f)` runs on every path through it, and
 * the early exits return literals. The initial value can never be
 * observed, so it is a dead store whatever it names. Task 1171 exempted
 * this shape outright; task 1387 narrowed the question to dataflow.
 */

#define ERR_CORRUPTION_DETECTED -0x006E
#define ERR_BAD_INPUT -0x0004
#define CHK(f) do { if ((ret = (f)) != 0) goto cleanup; } while (0)

int compute(int *out, int x);

int use(int *out, int x)
{
    int ret = ERR_CORRUPTION_DETECTED;

    if (x < 0) {
        return ERR_BAD_INPUT;
    }

    CHK(compute(out, x));
    CHK(compute(out, x + 1));

    ret = 0;

cleanup:
    return ret;
}
