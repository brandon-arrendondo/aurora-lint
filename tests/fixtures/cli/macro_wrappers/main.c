/* Invokes xfree()/xcalloc(), function-like macros defined in
 * include/wrappers.h. Without the prescan-collected function_macros table,
 * DCL31-C flags these as "called without prior declaration" — the curl
 * curlx_free/curlx_calloc false-positive class (task 185, Phase 2c-i). */
void process(void *p) {
    void *buf = xcalloc(4, 8);
    xfree(buf);
    xfree(p);
}
