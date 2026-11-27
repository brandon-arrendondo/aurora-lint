/*
 * Rule: ARR00-C
 * Source: synthetic
 * Status: PASS - A constant that sizes an array parameter is not itself a parameter
 *
 * `PATH_MAX` appears in each parameter list only as the size of
 * `resolved`. The local arrays it sizes have a constant length, not one a
 * caller chooses, so they are not variable-length arrays sized by a
 * parameter, whatever the function returns.
 */
#define PATH_MAX 4096

char *resolve(const char *path, char resolved[PATH_MAX])
{
    char left[PATH_MAX];
    left[0] = path[0];
    resolved[0] = left[0];
    return resolved;
}

int resolve_length(const char *path, char resolved[PATH_MAX])
{
    char left[PATH_MAX];
    left[0] = path[0];
    resolved[0] = left[0];
    return 1;
}
