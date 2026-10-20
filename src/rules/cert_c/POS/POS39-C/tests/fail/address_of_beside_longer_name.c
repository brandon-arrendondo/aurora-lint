/*
 * Rule: POS39-C
 * Source: aurora-lint
 * Status: FAIL - a uint32_t is received without ntohl()
 *
 * Beside the byte buffer `idx`, recv() also fills the uint32_t `id`, which
 * is used without a byte-order conversion.
 */
#include <stdint.h>
#include <sys/socket.h>

void read_index(int sock) {
    uint32_t id = 0;
    unsigned char idx[4];
    recv(sock, &idx, sizeof(idx), 0);
    recv(sock, &id, sizeof(id), 0);
    (void)id;
    (void)idx;
}
