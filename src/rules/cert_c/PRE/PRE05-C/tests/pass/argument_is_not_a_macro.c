/*
 * Rule: PRE05-C
 * Source: testcases
 * Status: PASS - Should NOT trigger PRE05-C violation
 *
 * The arguments to the stringizing and pasting macros are plain tokens that
 * no #define names, so stringizing or pasting them as written is the
 * intent. The helper's `_IMPL` suffix plays no part: the rule no longer
 * reads macro names.
 */

#define STRINGIFY_IMPL(x) #x
#define FIELD(prefix, name) prefix##_##name

const char *label = STRINGIFY_IMPL(ready);
int FIELD(config, timeout);
