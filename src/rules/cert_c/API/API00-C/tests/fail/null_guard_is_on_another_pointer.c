/*
 * Rule: API00-C
 * Source: real-world (task 745)
 * Status: FAIL - Should trigger API00-C violation
 */

/*
 * The counterpart to tests/pass/null_guard_reached_structurally.c. Finding a
 * guard the scan used to walk past must not become "an if statement appears
 * near this parameter". Task 664's sample contains a cohort of hostap
 * forwarding wrappers where a guard checks OTHER pointers and leaves the
 * flagged one unchecked, and aurora-lint's per-parameter attribution was right in
 * every one of them.
 *
 * The other functions here are cases the old TEXT matcher suppressed by
 * accident, because its pattern for a truthiness guard -- "(p)" -- also
 * matches a call that merely passes p, and its pattern for "p != 0" also
 * matches a test of the pointee, "*p != 0".
 *
 * None of these guards exits early, deliberately. An early-return guard is
 * classified before polarity is ever considered, and that path still credits
 * any parameter whose NAME appears in the condition text -- so writing these
 * with a `return` in the guard would test a different code path and pass for
 * the wrong reason.
 */

#include <stddef.h>

/*
 * The guard tests three fields of `h`, never the `addr` parameter.
 * From hostap src/ap/ap_drv_ops.c hostapd_sta_set_flags().
 */
struct driver_ops {
    int (*sta_set_flags)(void *priv, unsigned char *addr, int flags);
};
struct hostapd_data {
    struct driver_ops *driver;
    void *drv_priv;
};

int sta_set_flags(struct hostapd_data *h, unsigned char *addr, int flags)
{
    if (!h->driver || !h->drv_priv || !h->driver->sta_set_flags)
        return 0;
    return h->driver->sta_set_flags(h->drv_priv, addr, flags);
}

/*
 * `e` is compared against another pointer, never against NULL, and is
 * dereferenced in that very condition.
 * From hostap wpa_supplicant/p2p_supplicant.c wpas_p2p_deinit_iface().
 */
struct expdesc {
    int k;
    struct expdesc *next;
};

void deinit_iface(struct expdesc *e)
{
    if (e == e->next && e->k > 0) {
        e->k = 0;
    }
    e->next = NULL;
}

/*
 * A predicate CALL on the parameter is not a NULL test of it. The old text
 * pattern "(sc)" matched inside `sc_sporadic(sc)`.
 * From seL4 src/object/schedcontext.c schedContext_bindTCB() and
 * lua lcode.c luaK_exp2anyregup().
 */
int sc_sporadic(struct expdesc *sc);

int bind_sc(struct expdesc *sc)
{
    if (sc_sporadic(sc) && sc->k > 0) {
        sc->k = 0;
    }
    return sc->k;
}

/*
 * Testing the POINTEE is not testing the pointer: "base != 0" matched as a
 * substring of "*base != 0".
 * From pure-ftpd src/ls.c donlst().
 */
int chdir_to(const char *base);

int walk(const char *base)
{
    int failed = 0;

    if (*base != 0 && chdir_to(base) != 0) {
        failed = 1;
    }
    return failed + base[0];
}
