/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: PASS
 * Reason: A local bound to a handle returned by a lookup/registry accessor
 * (not a fresh allocation this function made) is a borrowed reference into
 * a longer-lived object. Allocating into one of its fields updates that
 * object, not something this function is responsible for freeing before it
 * returns -- the owning container releases it in its own teardown.
 * Modeled on real hostap (p2p_add_device()/p2p_create_device()) and curl
 * (ftp_done()/Curl_conn_meta_get()) shapes (task 1200).
 */

#include <stdlib.h>

struct entry {
    char *name;
};

struct entry *registry_find_entry(int id);

int update_entry(int id, const char *new_name) {
    struct entry *e = registry_find_entry(id);
    if (e == NULL) {
        return -1;
    }

    /* e is a handle into the registry's own persistent storage -- this
     * allocation belongs to the registry entry's lifetime, freed whenever
     * the registry itself tears the entry down, not here. */
    e->name = strdup(new_name);
    if (e->name == NULL) {
        return -1;
    }

    return 0;
}
