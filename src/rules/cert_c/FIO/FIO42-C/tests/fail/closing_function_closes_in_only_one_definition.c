/*
 * Rule: FIO42-C
 *
 * Status: FAIL - Should trigger FIO42-C violation
 *
 * finish_log() closes its stream in one #if arm only; the other definition
 * just flushes it. The caller compiles under both arms, so a build that
 * links the flushing definition never closes the file. A close is credited
 * only when every definition the call can link with closes.
 */
#include <stdio.h>

#ifdef KEEP_LOG_OPEN
void finish_log(FILE *f)
{
    fflush(f);
}
#else
void finish_log(FILE *f)
{
    fclose(f);
}
#endif

int write_log(const char *path)
{
    FILE *f = fopen(path, "w");
    if (f == NULL)
        return -1;
    fputs("done\n", f);
    finish_log(f);
    return 0;
}
