/*
 * Rule: MEM03-C
 * Source: custom
 * Status: FAIL - Should trigger MEM03-C violation
 * Description: wipe() overwrites its buffer in one #if arm only; the other
 * definition does nothing with it. The caller compiles under both arms, so a
 * build that links the empty definition frees the secret with its contents
 * intact. A clear is credited only when every definition the call can link
 * with clears.
 */

#include <stdlib.h>
#include <string.h>

#ifdef NO_WIPE
static void wipe(void *buf, size_t len) {
    (void)buf;
    (void)len;
}
#else
static void wipe(void *buf, size_t len) {
    memset(buf, 0, len);
}
#endif

int derive_secret(void) {
    unsigned char *password = malloc(64);
    if (password == NULL) {
        return -1;
    }
    password[0] = 2;
    wipe(password, 64);
    free(password);
    return 0;
}
