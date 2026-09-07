/*
 * Rule: MSC12-C
 * Status: FAIL - Empty plain `static` function body
 *
 * The boundary of the null-backend exception (task 1005): an empty
 * non-static definition of a header-prototyped function is an interface
 * being satisfied and is not reported, but a plain `static` one is
 * unreachable from outside its own translation unit, so it may really be
 * dead and stays flagged. No `inline` here either -- that is the separate
 * build-configuration-shim exception (see pass/testcases_static_inline_stub.c).
 */

static void local_noop(void)
{
}
