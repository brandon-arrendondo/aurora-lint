/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation. `rnd` is declared
 * with no initializer and passed BY VALUE (bare, cast to `unsigned char *`)
 * to `MY_RAND()`, a "pure forwarding" macro (task 589; curl's
 * `Curl_rand(a,b,c)` -> `Curl_rand_bytes(a,b,c)` pattern) whose body is just
 * a call to `real_rand_bytes()`, the actual function that writes through
 * its `out` argument. The macro's own body text has no assignment for the
 * macro-output-arg engine to see, so recognizing this write requires
 * following the forwarding call to `real_rand_bytes`'s own FunctionSummary
 * (`modifies_params`) and mapping its output-param index back through the
 * macro's own parameter position.
 */
struct ctx;

int real_rand_bytes(struct ctx *c, unsigned char *out, unsigned long num) {
    for (unsigned long i = 0; i < num; i++) {
        out[i] = (unsigned char)i;
    }
    return 0;
}

#define MY_RAND(a, b, c) real_rand_bytes(a, b, c)

void f(struct ctx *c) {
    unsigned char *rnd;
    MY_RAND(c, rnd, 16);
    (void)rnd[0];
}
