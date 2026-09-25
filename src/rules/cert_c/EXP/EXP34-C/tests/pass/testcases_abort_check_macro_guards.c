/*
 * Rule: EXP34-C
 * Source: testcases (assert-style macro no configuration compiles out)
 * Status: PASS - Should NOT trigger EXP34-C
 *
 * valkey's serverAssert (src/server.h) has one definition and no NDEBUG
 * arm: when its argument is false it reports and never returns. ADR-0011
 * basis 3 counts such a macro as a dominating check. Recognized by what
 * every definition expands to (analyze::check_macros), not by name:
 * `likely` and `valkey_unreachable` each have two build-flag arms, and both
 * arms of each preserve the check.
 */

#include <stdlib.h>
#include <string.h>

#if __GNUC__ >= 5
#define valkey_unreachable __builtin_unreachable
#else
#define valkey_unreachable abort
#endif

#if __GNUC__ >= 3
#define likely(x) __builtin_expect(!!(x), 1)
#else
#define likely(x) (x)
#endif

void _serverAssert(const char *estr, const char *file, int line);
void _serverAssertWithInfo(const void *c, const void *o, const char *estr, const char *file, int line);

#define serverAssertWithInfo(_c, _o, _e) \
    (likely(_e) ? (void)0 : (_serverAssertWithInfo(_c, _o, #_e, __FILE__, __LINE__), valkey_unreachable()))
#define serverAssert(_e) (likely(_e) ? (void)0 : (_serverAssert(#_e, __FILE__, __LINE__), valkey_unreachable()))
#define ModuleAssert(_e) ((_e) ? (void)0 : (report_failure(#_e, __FILE__, __LINE__), exit(1)))

void report_failure(const char *estr, const char *file, int line);

void split_at_colon(char *buf) {
    char *p = strchr(buf, ':');
    serverAssert(p != NULL);
    *p = 0;
}

void split_with_info(const void *c, char *buf) {
    char *p = strchr(buf, ':');
    serverAssertWithInfo(c, NULL, p);
    *p = 0;
}

void split_module(char *buf) {
    char *p = strchr(buf, ':');
    ModuleAssert(p);
    *p = 0;
}

/* The check proves a pointer and one of its fields, and the copy of the
 * field inherits the proof (valkey cluster_legacy.c
 * clusterAllReplicasThinkPrimaryIsFail). */
struct node {
    struct node *replicaof;
    int num_replicas;
};

struct node *myself = NULL;

int replicas_of(void) {
    serverAssert(myself != NULL && myself->replicaof);
    struct node *primary = myself->replicaof;
    return primary->num_replicas;
}
