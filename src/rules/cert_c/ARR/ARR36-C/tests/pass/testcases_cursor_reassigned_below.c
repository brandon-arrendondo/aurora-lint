/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR36-C violation
 */

/*
 * Rule: ARR36-C - Do not subtract or compare two pointers that do not refer to the same array
 * Status: PASS
 * Reason: A cursor measured against the object it walks, and only LATER
 *         re-pointed at a fresh allocation. Every comparison and subtraction
 *         here is written ABOVE that reassignment, so the base in force at
 *         each of them is the one established above it -- one object on both
 *         sides. Keeping a single base per name for a whole function let the
 *         last assignment decide what the operands fifty lines higher meant.
 *
 *         Distilled from hostap src/rsn_supp/tdls.c
 *         (wpa_tdls_send_discovery_response) and src/eap_peer/eap_pwd.c
 *         (eap_pwd_init).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct peer {
    unsigned char *rsnie;
    unsigned int rsnie_len;
};

/* `hdr` and `pos` both sit in peer->rsnie; `scratch` is a different object
 * entirely, and pos only joins it after both measurements are taken. */
void build_then_reuse(struct peer *peer, const char *tail)
{
    unsigned char *hdr = peer->rsnie;
    unsigned char *pos = hdr;
    unsigned char *scratch;

    pos += 8;
    if (pos > hdr) {
        printf("advanced\n");
    }
    peer->rsnie_len = (unsigned int)(pos - hdr);

    scratch = malloc(64);
    if (scratch == NULL) {
        return;
    }
    pos = scratch;
    strncpy((char *)pos, tail, 63);
    free(scratch);
}

/* `pos` and `end` both point into `phase1`; `copy` is a separate object that
 * pos is handed only after the length between them has been taken. */
char *split_then_copy(char *phase1)
{
    char *pos;
    char *end;
    char *copy;
    size_t len;

    pos = strstr(phase1, "id=");
    if (pos == NULL) {
        return NULL;
    }
    end = strchr(pos, ' ');
    if (end == NULL) {
        return NULL;
    }
    len = (size_t)(end - pos);

    copy = malloc(len + 1);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, pos, len);
    pos = copy;
    pos[len] = '\0';
    return copy;
}

int main(void)
{
    struct peer p;
    unsigned char raw[64] = {0};
    char phase1[32] = "id=one two";

    p.rsnie = raw;
    p.rsnie_len = 0;
    build_then_reuse(&p, "tail");
    free(split_then_copy(phase1));
    return 0;
}
