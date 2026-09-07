/*
 * Rule: MSC12-C
 * Status: PASS - the value of an assignment chosen by conditional
 *         compilation. tree-sitter has no preprocessor, so it sees the
 *         constant as a statement of its own rather than as the right-hand
 *         side of the `=` on the line above (curl's Curl_create_sspi_identity).
 */

struct identity { unsigned long flags; };

void set_flags(struct identity *identity)
{
    identity->flags = (unsigned long)
#ifdef SQC_TEST_UNICODE
        SQC_TEST_FLAG_UNICODE;
#else
        SQC_TEST_FLAG_ANSI;
#endif
}
