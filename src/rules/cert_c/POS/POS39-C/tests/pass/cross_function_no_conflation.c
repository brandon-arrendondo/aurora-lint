/*
 * Rule: POS39-C
 * Source: task 418 (task-389 sweep, whole-file tracking-map conflation)
 * Status: PASS - Should NOT trigger POS39-C violation
 *
 * `multi_byte_vars` was previously built by a single whole-translation-unit
 * walk with no per-function reset, so `func_a`'s unrelated local `uint32_t
 * id` leaked into `func_b`'s plain `int id` (received via `recv()`, not
 * itself a multi-byte type at all) and caused a bogus "received into 'id'
 * (uint32_t) without byte order conversion" report.
 */
#include <sys/socket.h>

void func_a(void) {
    uint32_t id;
    id = 42;
    (void)id;
}

void func_b(int sock) {
    int id;
    recv(sock, &id, sizeof(id), 0);
    (void)id;
}
