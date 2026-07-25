/*
 * Rule: MEM01-C
 * Source: testcases (task 321)
 * Status: PASS - Should NOT trigger MEM01-C violation
 * Description: The loop variable is reassigned inside the while condition
 * itself (`(entry = next_entry()) != NULL`) before any reuse each iteration,
 * so freeing it in the body is safe -- mirrors hostap's
 * wpa_supplicant/mesh_rsn.c mesh_rsn_auth_init() list-drain idiom.
 */

#include <stdlib.h>

struct entry {
    struct entry *next;
    int value;
};

struct entry *next_entry(struct entry *list);
void use_value(int v);

void drain_list(struct entry *list) {
    struct entry *entry;
    while ((entry = next_entry(list)) != NULL) {
        use_value(entry->value);
        free(entry);
    }
}
