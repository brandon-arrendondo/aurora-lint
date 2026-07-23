/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: PASS
 * Reason: The struct is a caller-owned function parameter (borrowed), not
 * locally declared/malloc'd in this function. Populating one of its fields
 * doesn't make this function responsible for freeing it before return -
 * ownership belongs to whoever owns the struct's lifetime (e.g. a separate
 * cleanup function called later by the caller). Modeled on a real-world
 * false positive in mosquitto's client_config_options_file().
 */

#include <stdlib.h>
#include <string.h>

struct mosq_config {
    char *options_file;
    char *host;
};

static int client_config_options_file(struct mosq_config *cfg, const char *path)
{
    if (!cfg || !path) {
        return 1;
    }

    cfg->options_file = strdup(path);

    return 0;
}

void client_config_cleanup(struct mosq_config *cfg)
{
    if (!cfg) {
        return;
    }
    free(cfg->options_file);
    cfg->options_file = NULL;
    free(cfg->host);
    cfg->host = NULL;
}
