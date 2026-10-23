/*
 * Rule: FIO14-C
 * Source: testcases
 * Status: FAIL - Should trigger FIO14-C violation
 * Settings: posix_version=none
 *
 * The target is declared not POSIX, so a binary stream need not support
 * SEEK_END meaningfully (C11 7.21.9.2p3), under every preset.
 */
#include <stdio.h>

void seek_end_of_binary(void) {
    FILE *fp = fopen("data.bin", "rb");
    if (fp != NULL) {
        fseek(fp, 0, SEEK_END);
        fclose(fp);
    }
}

void seek_end_of_binary_opened_by_fopen_s(const char *name) {
    FILE *fp = NULL;
    fopen_s(&fp, name, "rb");
    if (fp != NULL) {
        fseek(fp, 0, SEEK_END);
        fclose(fp);
    }
}
