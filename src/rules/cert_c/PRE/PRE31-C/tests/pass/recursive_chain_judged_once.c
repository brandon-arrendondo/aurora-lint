/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: forty mutually recursive functions that write nothing are pure;
 * each body is judged once (a regression to one walk per call path would
 * take about Fib(40) walks and time the test out).
 */

#include <assert.h>

static int f0(int n);
static int f1(int n);
static int f2(int n);
static int f3(int n);
static int f4(int n);
static int f5(int n);
static int f6(int n);
static int f7(int n);
static int f8(int n);
static int f9(int n);
static int f10(int n);
static int f11(int n);
static int f12(int n);
static int f13(int n);
static int f14(int n);
static int f15(int n);
static int f16(int n);
static int f17(int n);
static int f18(int n);
static int f19(int n);
static int f20(int n);
static int f21(int n);
static int f22(int n);
static int f23(int n);
static int f24(int n);
static int f25(int n);
static int f26(int n);
static int f27(int n);
static int f28(int n);
static int f29(int n);
static int f30(int n);
static int f31(int n);
static int f32(int n);
static int f33(int n);
static int f34(int n);
static int f35(int n);
static int f36(int n);
static int f37(int n);
static int f38(int n);
static int f39(int n);

static int f0(int n) { return n > 0 ? f1(n - 1) + f2(n - 2) : 0; }
static int f1(int n) { return n > 0 ? f2(n - 1) + f3(n - 2) : 0; }
static int f2(int n) { return n > 0 ? f3(n - 1) + f4(n - 2) : 0; }
static int f3(int n) { return n > 0 ? f4(n - 1) + f5(n - 2) : 0; }
static int f4(int n) { return n > 0 ? f5(n - 1) + f6(n - 2) : 0; }
static int f5(int n) { return n > 0 ? f6(n - 1) + f7(n - 2) : 0; }
static int f6(int n) { return n > 0 ? f7(n - 1) + f8(n - 2) : 0; }
static int f7(int n) { return n > 0 ? f8(n - 1) + f9(n - 2) : 0; }
static int f8(int n) { return n > 0 ? f9(n - 1) + f10(n - 2) : 0; }
static int f9(int n) { return n > 0 ? f10(n - 1) + f11(n - 2) : 0; }
static int f10(int n) { return n > 0 ? f11(n - 1) + f12(n - 2) : 0; }
static int f11(int n) { return n > 0 ? f12(n - 1) + f13(n - 2) : 0; }
static int f12(int n) { return n > 0 ? f13(n - 1) + f14(n - 2) : 0; }
static int f13(int n) { return n > 0 ? f14(n - 1) + f15(n - 2) : 0; }
static int f14(int n) { return n > 0 ? f15(n - 1) + f16(n - 2) : 0; }
static int f15(int n) { return n > 0 ? f16(n - 1) + f17(n - 2) : 0; }
static int f16(int n) { return n > 0 ? f17(n - 1) + f18(n - 2) : 0; }
static int f17(int n) { return n > 0 ? f18(n - 1) + f19(n - 2) : 0; }
static int f18(int n) { return n > 0 ? f19(n - 1) + f20(n - 2) : 0; }
static int f19(int n) { return n > 0 ? f20(n - 1) + f21(n - 2) : 0; }
static int f20(int n) { return n > 0 ? f21(n - 1) + f22(n - 2) : 0; }
static int f21(int n) { return n > 0 ? f22(n - 1) + f23(n - 2) : 0; }
static int f22(int n) { return n > 0 ? f23(n - 1) + f24(n - 2) : 0; }
static int f23(int n) { return n > 0 ? f24(n - 1) + f25(n - 2) : 0; }
static int f24(int n) { return n > 0 ? f25(n - 1) + f26(n - 2) : 0; }
static int f25(int n) { return n > 0 ? f26(n - 1) + f27(n - 2) : 0; }
static int f26(int n) { return n > 0 ? f27(n - 1) + f28(n - 2) : 0; }
static int f27(int n) { return n > 0 ? f28(n - 1) + f29(n - 2) : 0; }
static int f28(int n) { return n > 0 ? f29(n - 1) + f30(n - 2) : 0; }
static int f29(int n) { return n > 0 ? f30(n - 1) + f31(n - 2) : 0; }
static int f30(int n) { return n > 0 ? f31(n - 1) + f32(n - 2) : 0; }
static int f31(int n) { return n > 0 ? f32(n - 1) + f33(n - 2) : 0; }
static int f32(int n) { return n > 0 ? f33(n - 1) + f34(n - 2) : 0; }
static int f33(int n) { return n > 0 ? f34(n - 1) + f35(n - 2) : 0; }
static int f34(int n) { return n > 0 ? f35(n - 1) + f36(n - 2) : 0; }
static int f35(int n) { return n > 0 ? f36(n - 1) + f37(n - 2) : 0; }
static int f36(int n) { return n > 0 ? f37(n - 1) + f38(n - 2) : 0; }
static int f37(int n) { return n > 0 ? f38(n - 1) + f39(n - 2) : 0; }
static int f38(int n) { return n > 0 ? f39(n - 1) + f0(n - 2) : 0; }
static int f39(int n) { return n > 0 ? f0(n - 1) : 0; }

void h(int x) {
    assert(f0(x));
}
