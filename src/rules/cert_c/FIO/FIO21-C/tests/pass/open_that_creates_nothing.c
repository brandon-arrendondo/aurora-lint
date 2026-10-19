/*
 * Rule: FIO21-C
 * Source: regression
 * Status: PASS - Should NOT trigger FIO21-C violation
 *
 * Opens under /tmp that create nothing: fopen() in read mode and open()
 * without O_CREAT. Only a creating open is form (b).
 */

#include <stdio.h>
#include <fcntl.h>

int read_both(void) {
    FILE *fp = fopen("/tmp/existing.txt", "r");
    int fd = open("/var/tmp/existing.bin", O_RDONLY);
    if (fp != NULL) {
        fclose(fp);
    }
    return fd;
}
