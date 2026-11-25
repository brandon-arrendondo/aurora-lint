/*
 * Rule: MSC12-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger MSC12-C violation
 *
 * REGISTER(handler) expands to a whole constructor that ends in `}`, so it
 * is an item of its own and not part of the head of the static after it.
 * Its constructor attribute keeps the constructor, not `unused_helper`,
 * which nothing calls.
 */

#define REGISTER(fn) \
    static void __attribute__((constructor)) reg_##fn(void) { register_it(fn); }

void register_it(int (*f)(void));

static int handler(void) { return 0; }

REGISTER(handler)

static int unused_helper(int x) { /* VIOLATION */
    return x * 3;
}

int api(int x) { return x; }
