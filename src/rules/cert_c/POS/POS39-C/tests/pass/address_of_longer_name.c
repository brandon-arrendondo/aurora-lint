/*
 * Rule: POS39-C
 * Source: aurora-lint (misfire: `&id` matched inside `&idx`)
 * Status: PASS - Should NOT trigger POS39-C violation
 *
 * recv() fills the byte buffer `idx`. The uint32_t `id` is never received
 * into, but its address spelling `&id` is a prefix of `&idx`.
 */
#include <stdint.h>
#include <sys/socket.h>

void read_index(int sock) {
    uint32_t id = 0;
    unsigned char idx[4];
    recv(sock, &idx, sizeof(idx), 0);
    (void)id;
    (void)idx;
}
