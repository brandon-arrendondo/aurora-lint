/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: A heap-held password passed as mysql_real_connect's passwd argument is a credential; the block is never locked.
 */

#include <mysql.h>
#include <stdlib.h>
#include <string.h>

MYSQL *connect_db(MYSQL *db, const char *typed) {
    char *pw = strdup(typed);
    MYSQL *conn;
    if (pw == NULL) return NULL;
    conn = mysql_real_connect(db, "localhost", "ftp", pw, "auth", 0, NULL, 0);
    free(pw);
    return conn;
}
