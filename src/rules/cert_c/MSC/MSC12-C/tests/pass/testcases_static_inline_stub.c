/*
 * Rule: MSC12-C
 * Status: PASS - Should NOT trigger MSC12-C violation
 */

/*
 * Reason: an empty `static inline` function is a build-configuration shim,
 * not dead code. It is the `#else` arm of a feature `#ifdef` in a header,
 * defined so every call site compiles unchanged when the feature is off --
 * deleting it breaks the build of every translation unit that calls it
 * (task 999; hostap alone carries 226 of these, e.g.
 * `static inline void wpas_nan_flush(struct wpa_supplicant *wpa_s) {}`).
 *
 * The storage class is the signal, not the file name or the function name.
 * A plain empty `static` function with no `inline` stays flagged -- nothing
 * outside its own translation unit can call it, so it really may be dead.
 */

struct feature_state;

static inline void feature_flush(struct feature_state *st)
{
    (void)st;
}

static inline void feature_deinit(struct feature_state *st) {}
