/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: forward's inner `pw` shadows its parameter, so handing it to pam_set_item as PAM_AUTHTOK makes the (locked) local sensitive, not the caller's buffer passed as the parameter.
 */

#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

void forward(pam_handle_t *h, char *pw) {
    (void)pw;
    {
        char pw[64];
        mlock(pw, sizeof pw);
        if (fgets(pw, sizeof pw, stdin) != NULL) {
            pam_set_item(h, PAM_AUTHTOK, pw);
        }
    }
}

void caller(pam_handle_t *h) {
    char *label = malloc(64);
    if (label == NULL) {
        return;
    }
    strcpy(label, "session");
    forward(h, label);
    free(label);
}
