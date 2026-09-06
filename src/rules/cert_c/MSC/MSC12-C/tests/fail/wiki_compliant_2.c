/*
 * Rule: MSC12-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC12-C violation. CERT's "Compliant
 * Solution" label here is about a DIFFERENT structural point (fixing
 * an off-by-one loop bound makes the inner "if" reachable, per the
 * live wiki) -- it isn't claiming the empty comment-only if-body
 * itself is meaningful code. The if-body below is mechanically empty
 * with no effect, which is exactly what MSC12-C targets; aurora-lint's
 * detection is correct even though the wiki used a placeholder
 * comment instead of real code for illustration.
 */

int s_loop(char *s) {
    size_t i;
    size_t len = strlen(s);
    for (i=0; i < len; i++) {
        /* Code that doesn't change s, i, or len */
      if (s[i+1] == '\0') {
        /* This code is now reached */
      }
    }
    return 0;
}