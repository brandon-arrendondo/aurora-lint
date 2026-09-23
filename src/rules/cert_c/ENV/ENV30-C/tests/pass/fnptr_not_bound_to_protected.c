/*
 * Rule: ENV30-C
 * Source: real-world
 * Status: PASS - Should NOT trigger ENV30-C violation
 */

/*
 * The two ways a call through a function pointer must NOT pick up
 * protected provenance: the pointer is never bound to a protected
 * function, and a local of the same name shadows one that is.
 */

#include <stdlib.h>
#include <string.h>

static char buffer[64];

static char *read_config(const char *name) {
    (void)name;
    return buffer;
}

static char *(*config_reader)(const char *name);
static char *(*env_reader)(const char *name);

void bind_readers(void) {
    config_reader = &read_config;
    env_reader = &getenv;
}

void overwrite_config(void) {
    char *value = config_reader("SETTING");

    if (value != NULL) {
        /* COMPLIANT: config_reader returns this program's own buffer */
        strcpy(value, "default");
    }
}

void overwrite_shadowed(void) {
    /* The local binding shadows the file-scope env_reader for the rest of
     * this scope, so this call cannot be the one bound to getenv. */
    char *(*env_reader)(const char *name) = &read_config;
    char *value = env_reader("SETTING");

    if (value != NULL) {
        /* COMPLIANT: the pointer called here is read_config */
        strcpy(value, "default");
    }
}
