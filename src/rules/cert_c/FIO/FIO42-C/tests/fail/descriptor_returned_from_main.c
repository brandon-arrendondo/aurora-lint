/*
 * Rule: FIO42-C
 *
 * Status: FAIL - Should trigger FIO42-C violation
 *
 * Returning from main ends the program: the value goes to the host
 * environment, not to a caller that could close the descriptor.
 */
#include <fcntl.h>

int main(void)
{
    int fd = open("settings", O_RDONLY);
    return fd;
}
