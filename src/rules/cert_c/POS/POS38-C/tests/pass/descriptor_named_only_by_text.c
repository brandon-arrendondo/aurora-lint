/*
 * Rule: POS38-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger POS38-C violation
 *
 * Shapes in which one fork() arm does not touch the opened descriptor: the
 * descriptor's name appears only inside a string literal, the stream comes
 * from popen() (which is not open()), and the child's descriptor is a
 * shadowing local of the same name.
 */
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

void name_in_string(void)
{
    char c;
    int fd = open("data", O_RDWR);
    pid_t pid = fork();
    if (pid == 0) {
        printf("child fd test\n");
    } else {
        read(fd, &c, 1);
    }
}

void pipe_stream(void)
{
    FILE *p = popen("ls", "r");
    pid_t pid = fork();
    if (pid == 0) {
        fputs("child\n", stdout);
    } else {
        fgetc(p);
    }
}

void shadowing_local(void)
{
    char c;
    int fd = open("data", O_RDWR);
    pid_t pid = fork();
    if (pid == 0) {
        int fd = 3;
        read(fd, &c, 1);
    } else {
        read(fd, &c, 1);
    }
}
