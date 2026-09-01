/*
 * Rule: POS39-C
 * Source: task 418 (task-389 sweep, whole-file tracking-map conflation)
 * Status: FAIL - Should trigger POS39-C violation
 *
 * `converted_vars` was previously a single whole-translation-unit
 * HashSet<String>, so a conversion in one function (`func_a`'s compliant
 * `num = ntohl(num)`) masked a missing conversion on an unrelated
 * same-named variable in a different function (`func_b`'s `num`), losing
 * a genuine violation. Per-function scoping recovers it.
 */
#include <sys/socket.h>

void func_a(int sock) {
    uint32_t num;
    recv(sock, &num, sizeof(num), 0);
    num = ntohl(num);
    (void)num;
}

void func_b(int sock) {
    uint32_t num;
    recv(sock, &num, sizeof(num), 0);
    (void)num;
}
