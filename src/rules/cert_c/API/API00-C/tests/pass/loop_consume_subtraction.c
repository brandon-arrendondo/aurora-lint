/*
 * Rule: API00-C
 * Source: custom
 * Status: PASS - Should NOT trigger API00-C violation
 * Description: The loop-consume idiom -- a size parameter a loop draws down
 * (task 740). rc4_skip and sha1_prf are bounded by an ordering loop condition
 * and were already suppressed by guard_dominance; bufq_write_pass
 * (`while (len) { len -= n; }`) and hmac_sha256_kdf (`for (;;)` with
 * `if (pos == outlen) break;`) are the two shapes whose loop control is not
 * an ordering comparison, and are what utility::cert_c::loop_consumption
 * recognizes.
 *
 * Honest limit, from the adjudication: curl's `len -= n` is bounded by
 * n <= len, which is what Curl_bufq_write wrote through its out-param -- a
 * callee contract, not a local fact. It is suppressed on the loop guard and
 * the decrement alone, so treat it as incidentally covered rather than proven.
 */


void rc4_skip(size_t skip)
{
    u8 skip_buf[16];
    size_t len;
    while (skip >= sizeof(skip_buf)) {
        len = sizeof(skip_buf);
        skip -= len;
    }
}

void sha1_prf(size_t buf_len)
{
    size_t pos = 0, plen;
    while (pos < buf_len) {
        plen = buf_len - pos;
        pos += plen;
    }
}

void hmac_sha256_kdf(size_t outlen)
{
    size_t pos = 0, clen;
    for (;;) {
        if (pos == outlen)
            break;
        clen = outlen - pos;
        pos += clen;
    }
}

void bufq_write_pass(size_t len)
{
    size_t n = 1;
    while (len) {
        len -= n;
    }
}
