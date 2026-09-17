/*
 * Rule: EXP02-C
 * Source: task 1151/1154, mirroring mbedtls's library/dhm.c
 *   mbedtls_dhm_read_params (benchmark_adjudication data/mbedtls/
 *   adjudication.csv library/dhm.c:154/155) and the same "assign-and-test
 *   abort chain" reason recorded for curl, hostap, valkey and ventoy
 * Status: PASS - Should NOT trigger EXP02-C violation
 *
 * `(ret = f()) != 0 || (ret = g()) != 0` is the standard sequential
 * fallible-step/abort-on-first-failure chain used throughout crypto/init
 * code: each `||` link only runs once every earlier one has already
 * failed, and the assigned value is exactly what the chain's own boolean
 * logic tests -- not a side effect the surrounding condition is blind to.
 */
int parse_bignum(int *out);

int read_params(void) {
    int ret;
    int p, g;
    if ((ret = parse_bignum(&p)) != 0 || (ret = parse_bignum(&g)) != 0) {
        return ret;
    }
    return 0;
}

/* Negation-wrapped form of the same idiom, distinct step variables. */
void *alloc_buf(int size);

int build_buffers(int len) {
    void *a, *b;
    if (!(a = alloc_buf(len)) || !(b = alloc_buf(len))) {
        return -1;
    }
    return 0;
}

/* Bare (untested) assignment as the guarded step, per hostap's
 * src/ap/airtime_policy.c: the assignment only runs -- and only needs to
 * run -- once the guard indicates the value has actually changed. */
int set_weight(int handle, int weight);

int apply_weight_if_changed(int current_weight, int new_weight, int handle) {
    int ret = 0;
    if (new_weight != current_weight && (ret = set_weight(handle, new_weight))) {
        return ret;
    }
    return 0;
}
