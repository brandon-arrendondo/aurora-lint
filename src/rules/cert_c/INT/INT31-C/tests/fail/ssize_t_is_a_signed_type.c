/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - An ssize_t is signed, whatever its name shares with size_t
 * Settings: data_model=lp64
 * Expect: count=2
 *
 * `read` returns -1 on error, so converting its `ssize_t` result to an
 * unsigned type can change its sign, and converting it to an `int` can
 * lose its high bits.
 */

#include <sys/types.h>
#include <unistd.h>

void sink(long);

void read_count(int fd, char *buf, size_t len)
{
    ssize_t res = read(fd, buf, len);
    unsigned int count = (unsigned int)res; /* Expect: here */
    int n = (int)res;                       /* Expect: here */
    sink(count + n);
}
