/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * A get-or-create constructor allocates the object, links it into a
 * container the caller handed in, and returns it. The caller that drops
 * the result leaks nothing: the container still holds the block, and the
 * container's own teardown releases it. The summary records the escape
 * (`returned_value_escapes`) from the body -- here both routes: a store
 * rooted in a parameter, and a hand-off to a callee whose own summary
 * stores its argument (an interior pointer, the intrusive-list idiom) --
 * and MEM31-C treats the result as borrowed (hostap bss_get /
 * ap_sta_add, curl curl_slist_append).
 */
#include <stdlib.h>

struct dl_list {
    struct dl_list *next;
    struct dl_list *prev;
};

static void dl_list_add(struct dl_list *list, struct dl_list *item) {
    item->next = list->next;
    item->prev = list;
    list->next->prev = item;
    list->next = item;
}

struct sta {
    struct dl_list list;
    int addr;
};

struct hapd {
    struct dl_list sta_list;
    struct sta *last;
    int num_sta;
};

/* Route 1: an interior pointer handed to a callee that stores it. */
static struct sta *ap_sta_add(struct hapd *hapd, int addr) {
    struct sta *sta = calloc(1, sizeof(*sta));
    if (!sta) {
        return NULL;
    }
    sta->addr = addr;
    dl_list_add(&hapd->sta_list, &sta->list);
    hapd->num_sta++;
    return sta;
}

/* Route 2: the object itself stored through a parameter. */
static struct sta *sta_get_or_create(struct hapd *hapd, int addr) {
    struct sta *sta = malloc(sizeof(*sta));
    if (!sta) {
        return NULL;
    }
    sta->addr = addr;
    hapd->last = sta;
    return sta;
}

void handle_assoc(struct hapd *hapd, int addr) {
    struct sta *sta = ap_sta_add(hapd, addr);
    if (!sta) {
        return;
    }
    sta->addr++;
}

void handle_auth(struct hapd *hapd, int addr) {
    struct sta *sta = sta_get_or_create(hapd, addr);
    if (sta) {
        sta->addr++;
    }
}
