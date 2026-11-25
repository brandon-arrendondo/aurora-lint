/*
 * Rule: MSC12-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger MSC12-C violation
 *
 * REG expands to a whole constructor in one arm and to nothing in the
 * other. Neither arm is an attribute of the static after the invocation:
 * the constructor attribute belongs to the constructor the item defines,
 * so `dead`, which nothing calls, is reported.
 */

#ifdef USE_CTOR
#define REG(fn) static void __attribute__((constructor)) reg_##fn(void) { (void)fn; }
#else
#define REG(fn)
#endif

int x;

REG(x)
static int dead(void) { /* VIOLATION */
    return 1;
}

int api(void) { return 0; }
