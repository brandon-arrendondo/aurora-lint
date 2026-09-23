/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 *
 * Guards the borrowed-result credit (task 1227) from over-reach: a
 * constructor that takes a container parameter but only READS it -- no
 * store rooted in it, no hand-off to a storing callee -- has not linked
 * its object anywhere. The result is the caller's to free, and dropping
 * it is the leak MEM31-C exists for.
 */
#include <stdlib.h>

struct sta {
    int addr;
    int idx;
};

struct hapd {
    int num_sta;
};

static void note_sta(const struct sta *sta) {
    (void)sta;
}

static struct sta *sta_new(struct hapd *hapd, int addr) {
    struct sta *sta = malloc(sizeof(*sta));
    if (!sta) {
        return NULL;
    }
    sta->addr = addr;
    sta->idx = hapd->num_sta;
    note_sta(sta);
    return sta;
}

void handle_assoc(struct hapd *hapd, int addr) {
    struct sta *sta = sta_new(hapd, addr);
    if (!sta) {
        return;
    }
    sta->addr++;
}
