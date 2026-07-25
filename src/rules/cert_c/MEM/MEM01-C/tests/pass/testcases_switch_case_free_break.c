/*
 * Rule: MEM01-C
 * Source: testcases (task 320)
 * Status: PASS - Should NOT trigger MEM01-C violation
 * Description: Each switch case frees and reassigns/returns independently,
 * so a free() in one arm must not be treated as reachable-then-reused by
 * code that follows the switch lexically -- mirrors hostap's
 * wpa_supplicant/wpa_cli.c main() option-parsing switch and
 * wpa_supplicant/ctrl_iface_named_pipe.c's error-handling switch (task 320).
 */

#include <stdlib.h>
#include <string.h>

char *dup_str(const char *s);

void option_parse(int opt, const char *optarg) {
    char *ctrl_ifname = NULL;

    switch (opt) {
    case 'i':
        free(ctrl_ifname);
        ctrl_ifname = dup_str(optarg);
        break;
    case 'v':
        break;
    default:
        break;
    }

    free(ctrl_ifname);
}

int handle_pipe_error(void *dst_pipe, char *dst) {
    switch (opt_error()) {
    case 1:
        break;
    default:
        free(dst);
        return -1;
    }

    return 0;
}

int opt_error(void);
