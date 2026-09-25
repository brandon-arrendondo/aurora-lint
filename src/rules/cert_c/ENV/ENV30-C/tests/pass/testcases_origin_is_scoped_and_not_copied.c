/*
 * Rule: ENV30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ENV30-C violation
 */

/*
 * Rule: ENV30-C - Do not modify the object referenced by the return value
 *       of certain functions
 * Status: PASS
 * Reason: No modified variable holds strerror()'s own storage. The second
 *         `errors` is a different variable from the one in the failure
 *         block, and sharing its name does not share its origin. And a
 *         buffer that a formatting call builds from strerror()'s text is a
 *         new object: the call copied the string, it did not return it.
 *
 *         Distilled from valkey src/acl.c, ACLLoadFromFile.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

typedef char *sds;
sds sdsempty(void);
sds sdscatprintf(sds s, const char *fmt, ...);
sds sdscat(sds s, const char *t);

sds load(const char *filename, int n)
{
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        sds errors = sdscatprintf(sdsempty(), "Error loading %s: %s", filename,
                                  strerror(errno));
        return errors;
    }
    sds errors = sdsempty();
    for (int i = 0; i < n; i++)
        errors = sdscatprintf(errors, "line %d. ", i);
    errors = sdscat(errors, "done");
    fclose(fp);
    return errors;
}

sds describe(const char *filename)
{
    sds e = sdscatprintf(sdsempty(), "%s", strerror(errno));
    e = sdscat(e, filename);
    return e;
}
