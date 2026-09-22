/*
 * Rule: ENV30-C
 * Source: aurora_lint 1433
 * Status: FAIL - Should trigger ENV30-C violation
 */

/*
 * A file-scope function POINTER bound to getenv still returns the
 * environment string, so modifying what it hands back is the same
 * violation as modifying getenv's own return. lua's lua.c is the shape:
 * the pointer is declared at file scope, bound in one function and called
 * from another, and only one of its two bindings is the real getenv.
 */

#include <stdlib.h>
#include <string.h>

static char *no_getenv(const char *name) {
    (void)name;
    return NULL;
}

static char *(*env_reader)(const char *name);

void bind_env_reader(int ignore_environment) {
    if (ignore_environment) {
        env_reader = &no_getenv;
    } else {
        env_reader = &getenv;
    }
}

void overwrite_path(void) {
    char *path = env_reader("PATH");

    if (path != NULL) {
        /* VIOLATION: writes through a pointer that getenv may have returned */
        strcpy(path, "/tmp");
    }
}
