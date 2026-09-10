/*
 * Rule: EXP34-C
 * Source: testcases (mosquitto bridge_topic.c cohort)
 * Status: PASS - `use_prefix` is static and every call site guards its
 *         pointer, so the `!prefix` disjunct cannot be what made the
 *         condition true and `prefix` is non-null inside the branch.
 *
 * The shape is mosquitto src/bridge_topic.c:62, where bridge__create_prefix
 * opens with
 *
 *   if(!prefix || strlen(prefix) != 0){
 *
 * and both of its call sites are wrapped in `if(local_prefix)` /
 * `if(remote_prefix)`. Reporting here needs the disjunctive edge to join to
 * PossiblyNull, which is correct in general -- `A || B` being true says only
 * that one of them held -- but wrong for a parameter no caller can pass null.
 *
 * The distinction that makes this pass is PROOF vs VOTE: a `NotNull` in
 * `callsite_param_null_states` is a majority verdict that lets an `Unknown`
 * caller abstain, while `callsite_param_proven_nonnull` requires every call
 * site to have proved it. Only the second may discard a disjunct, and only
 * for a function with internal linkage, where the scanned call sites are
 * provably all of them.
 */

#include <string.h>

extern int check_topic(const char *s);
extern void emit(const char *fmt, const char *s);

static int use_prefix(const char *prefix)
{
    if (!prefix || strlen(prefix) != 0) {
        if (check_topic(prefix) != 0) {
            emit("bad prefix '%s'", prefix);
            return 1;
        }
    }
    return 0;
}

void configure(const char *local_prefix, const char *remote_prefix)
{
    if (local_prefix) {
        use_prefix(local_prefix);
    }
    if (remote_prefix) {
        use_prefix(remote_prefix);
    }
}
