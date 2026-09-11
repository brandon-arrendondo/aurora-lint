/*
 * Rule: MEM03-C
 * Source: custom
 * Status: FAIL - Should trigger MEM03-C violation
 * Description: Guard for recognising clearing wrappers by their bodies. These
 * helpers are named like clearers and receive the secret, but neither
 * overwrites it: one only logs its length, the other overwrites a DIFFERENT
 * buffer. Neither may be credited with clearing the secret, which therefore
 * leaves scope (and is freed) with its contents intact.
 */

#include <stdlib.h>
#include <string.h>

static size_t logged;

static void zeroize_log(void *buf, size_t len) {
    (void)buf;
    logged = len;
}

static void zeroize_other(void *buf, size_t len) {
    static unsigned char scratch[64];
    (void)buf;
    memset(scratch, 0, len < sizeof(scratch) ? len : sizeof(scratch));
}

int leaves_secret_intact(void) {
    unsigned char tmp_secret[32];
    unsigned char *password = malloc(64);
    if (password == NULL) {
        return -1;
    }
    tmp_secret[0] = 1;
    password[0] = 2;
    zeroize_log(tmp_secret, sizeof(tmp_secret));
    zeroize_other(password, 64);
    free(password);
    return 0;
}
