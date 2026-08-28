/*
 * Rule: MSC23-C
 * Source: task 347 (real-world false-positive regression test)
 * Status: PASS - a text-mode stream read via fgets(), with an unrelated
 * pointer-walk increment in a nested loop and a conditional counter
 * elsewhere in the same outer loop, must not be flagged. Neither increment
 * is an unconditional per-character byte counter paired with a
 * single-character read (sqlite's sqllogFindFile / mosquitto's
 * proc-cmdline scanner / pure-ftpd's bounded timestamp-digit index all hit
 * this shape before the loop-shape was tightened).
 */

#include <stdio.h>
#include <string.h>

void scan_lines(const char *path) {
    FILE *fd = fopen(path, "r");
    if (fd == 0) {
        return;
    }
    while (feof(fd) == 0) {
        char line[256];
        if (fgets(line, sizeof(line), fd)) {
            char *z = line;
            /* Unrelated pointer walk in a nested loop -- not a byte count. */
            while (*z >= '0' && *z <= '9') {
                z++;
            }
        }
    }
    fclose(fd);
}

void scan_digits(const char *path) {
    int c;
    int instamp = -1;
    char digits[16];
    FILE *fp = fopen(path, "r");
    if (fp == 0) {
        return;
    }
    while ((c = getc(fp)) != EOF) {
        /* Conditional, bounded index -- not an unconditional byte counter. */
        if (instamp >= 0) {
            if (instamp < (int)(sizeof digits - 1)) {
                digits[instamp] = (char)c;
                instamp++;
            }
        }
    }
    fclose(fp);
}
