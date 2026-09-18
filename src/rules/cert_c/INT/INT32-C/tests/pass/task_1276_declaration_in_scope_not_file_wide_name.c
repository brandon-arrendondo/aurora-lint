/*
 * Rule: INT32-C
 * Source: task 1276 (hostap src/ap/wpa_auth.c:5131 and :5022 -- `size_t
 *         wpa_ie_len` inside `SM_STATE(WPA_PTK, PTKINITNEGOTIATING) { ... }`,
 *         `int wpa_ie_len` in another function)
 * Status: PASS - Should NOT trigger INT32-C violation
 * Reason: `wpa_ie_len` here is size_t, so `wpa_ie_len + kde_len(sm)` and
 *         `wpa_ie_len -= ie_len` are unsigned arithmetic. The function is
 *         declared through a macro, so its body is not a parsed
 *         `function_definition` and the rule fell back to its FILE-WIDE,
 *         name-keyed type map -- where the OTHER function's `int wpa_ie_len`
 *         answered (ADR-0006: a name is not a variable). The occurrence now
 *         resolves to its own declaration first; the map is only a fallback
 *         for names this file does not declare at all.
 */

#include <stddef.h>
#include <stdlib.h>

struct sm {
    int x;
    const unsigned char *wpa_ie;
};

#define SM_STATE(machine, state) static void sm_##machine##_##state##_Enter(struct sm *sm)

static int kde_len(struct sm *sm)
{
    return sm->x;
}

static size_t sink;

SM_STATE(WPA_PTK, PTKINITNEGOTIATING)
{
    size_t gtk_len, total = 0, wpa_ie_len;
    size_t ie_len = (size_t)atoi("4");

    wpa_ie_len = (size_t)atoi("40");
    gtk_len = 0;
    wpa_ie_len -= ie_len;
    total = wpa_ie_len + kde_len(sm);
    sink = total + gtk_len;
}

int other_function(const unsigned char *wpa_ie)
{
    int wpa_ie_len, secure = 0;

    wpa_ie_len = wpa_ie[1];
    return wpa_ie_len + secure;
}
