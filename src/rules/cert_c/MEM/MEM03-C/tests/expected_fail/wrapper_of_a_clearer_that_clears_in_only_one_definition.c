/*
 * Rule: MEM03-C
 * Source: custom
 * Status: EXPECTED_FAIL - a known gap, not detected yet
 * Description: scrub() has one definition, which hands its buffer to wipe();
 * wipe() overwrites it in one #if arm only. In a build that links the empty
 * wipe() neither function clears, so the secret is freed with its contents
 * intact.
 *
 * A definition is credited through a forward from what SOME definition of
 * the callee does, so scrub() reads as clearing. Asking every definition of
 * the callee waits on modelling which definitions link together, as the
 * same gap in MEM31-C does.
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

static void scrub(void *buf, size_t len) {
    wipe(buf, len);
}

int derive_secret(void) {
    unsigned char *password = malloc(64);
    if (password == NULL) {
        return -1;
    }
    password[0] = 2;
    scrub(password, 64);
    free(password);
    return 0;
}
