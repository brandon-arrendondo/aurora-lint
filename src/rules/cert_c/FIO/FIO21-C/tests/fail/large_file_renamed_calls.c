/*
 * Rule: FIO21-C
 * Source: regression
 * Status: FAIL - Should trigger FIO21-C violation
 *
 * glibc's headers rename fopen, open and tmpfile to their large-file
 * functions when a build sets _FILE_OFFSET_BITS=64, so the calls reach
 * fopen64, open64 and tmpfile64. Those are the same functions, and the
 * calls are judged as written.
 */

#include <fcntl.h>
#include <stdio.h>

#define fopen fopen64
#define open open64

FILE *fopen64(const char *path, const char *mode);
int open64(const char *path, int flags, ...);

int create_both(void) {
    FILE *fp = fopen("/tmp/session.dat", "w");
    if (fp != NULL) {
        fclose(fp);
    }
    return open("/var/tmp/session.lock", O_WRONLY | O_CREAT, 0600);
}
