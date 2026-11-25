/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: `create_new` hands back the stream `fdopen` returned, and
 * `open_log` the stream `create_new` returned. Neither is a heap block,
 * whatever the name shape suggests: closing the stream is FIO42-C's
 * concern, and every caller here closes it anyway.
 */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static FILE *create_new(const char *name)
{
    int fd2;
    FILE *fp2;

    if ((fd2 = open(name, O_CREAT | O_WRONLY, 0700)) == -1)
        return NULL;
    if ((fp2 = fdopen(fd2, "w")) == NULL) {
        close(fd2);
        return NULL;
    }
    return fp2;
}

static FILE *create_log(const char *name)
{
    return create_new(name);
}

int step(FILE *f);

int add(const char *name)
{
    FILE *fp2;

    if ((fp2 = create_new(name)) == NULL)
        return -1;
    if (step(fp2) < 0)
        goto bye;
    fclose(fp2);
    return 0;
bye:
    fclose(fp2);
    return -1;
}

int add_log(const char *name)
{
    FILE *log = create_log(name);

    if (log == NULL)
        return -1;
    step(log);
    fclose(log);
    return 0;
}
