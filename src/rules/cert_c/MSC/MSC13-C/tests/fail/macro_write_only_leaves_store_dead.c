/*
 * Rule: MSC13-C
 * Source: mosquitto src/persist.h + src/persist_read_v234.c (task 965)
 * Status: FAIL - Should trigger MSC13-C violation
 *
 * `read_e` only ever WRITES `rc` and jumps; it never reads it. So the
 * initializer `int rc = MOSQ_ERR_UNKNOWN;` is dead on every path -- the
 * macro's own store kills it on the error path, `rc = MOSQ_ERR_SUCCESS`
 * kills it on the fallthrough -- and the dead store is a true positive.
 *
 * The dead-store pass used to fold every free identifier in a macro body
 * into the statement's read set, with no read/write distinction, which made
 * the macro's assignment to `rc` look like a read and resurrected the dead
 * store. Only a read makes a previously-active definition live. The
 * unused-variable pass is a different question and still counts the write:
 * a variable a macro writes is used.
 */

#include <stdio.h>

#define MOSQ_ERR_SUCCESS 0
#define MOSQ_ERR_UNKNOWN 7

#define read_e(f, b, c) if(fread(b,1,c,f) != c){ rc = MOSQ_ERR_UNKNOWN; goto error; }

int persist_read_chunk(FILE *db_fptr, char *buf, int len)
{
    int rc = MOSQ_ERR_UNKNOWN;

    read_e(db_fptr, buf, len);
    rc = MOSQ_ERR_SUCCESS;
    return rc;
error:
    return rc;
}
