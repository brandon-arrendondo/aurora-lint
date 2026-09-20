/*
 * Rule: MSC13-C
 * Source: mbedtls MBEDTLS_MPI_CHK idiom (task 1387)
 * Status: FAIL - Should trigger MSC13-C violation
 *
 * `ret = 0;` is overwritten by the CHK macro's `ret = (f)` on every path
 * through the invocation -- the write is in the macro's if-condition, not
 * its body -- and `cleanup: return ret` is reached only through it.
 */

#define CHK(f) do { if ((ret = (f)) != 0) goto cleanup; } while (0)

int compute(int x);

int use(int x)
{
    int ret;

    ret = 0;
    CHK(compute(x));
    ret = compute(x + 1);

cleanup:
    return ret;
}
