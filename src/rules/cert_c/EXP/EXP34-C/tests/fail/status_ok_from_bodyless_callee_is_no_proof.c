/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * `rc == SQLITE_OK` says only what prepare() returned. prepare() has no body
 * in the scanned source to show it stores a non-null statement before
 * returning SQLITE_OK, so `p` is still the NULL it was initialized to as far
 * as anything proves.
 */
#define SQLITE_OK 0

struct stmt { int n; };
int prepare(const char *sql, struct stmt **pp);

int column_count(const char *sql) {
    struct stmt *p = 0;
    int rc = prepare(sql, &p);
    if (rc == SQLITE_OK) {
        return p->n;
    }
    return -1;
}
