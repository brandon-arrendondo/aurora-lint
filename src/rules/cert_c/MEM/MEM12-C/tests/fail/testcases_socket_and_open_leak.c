/*
 * Rule: MEM12-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM12-C violation
 *
 * open()/socket() are part of the resource-acquisition set migrated to
 * call_roles::is_resource_acquisition_text (task 499); previously
 * untested at the rule level. Modeled on tests/fail/wiki_posix.c's
 * fopen/malloc shape.
 */

#include <fcntl.h>
#include <sys/socket.h>

int do_something(void) {
    int fd = open("some_file", O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        close(fd);
        return -1;
    }

    int buf = 4096;
    void *scratch = malloc(buf);
    if (scratch == NULL) {
        close(fd);
        return -1;  /* Forgot to close sock!! */
    }

    /* ... more code ... */

    close(fd);
    close(sock);
    free(scratch);
    return 0;
}
