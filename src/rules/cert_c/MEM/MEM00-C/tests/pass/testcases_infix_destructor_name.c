/*
 * Rule: MEM00-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM00-C violation (task 318)
 * Description: A "<module>_<action>_<subject>" compound name where the
 * destructor action word sits in the middle (not a prefix/suffix) still
 * signals a dedicated cleanup helper, e.g. hostap's
 * hostapd_config_free_radius() / hostapd_cleanup_iface().
 */

#include <stdlib.h>

struct radius_server {
    char *shared_secret;
};

void hostapd_config_free_radius(struct radius_server *servers, int num_servers) {
    int i;
    for (i = 0; i < num_servers; i++) {
        free(servers[i].shared_secret);
    }
    free(servers);
}
