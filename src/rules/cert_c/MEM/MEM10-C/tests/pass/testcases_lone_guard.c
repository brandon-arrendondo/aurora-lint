/*
 * Rule: MEM10-C
 * Source: task 595 (pure-ftpd adversarial re-verify)
 * Status: PASS - A single, isolated early-return NULL guard is the standard,
 * universally-accepted idiom (pure-ftpd log_mysql.c:54 / log_pgsql.c:248
 * style: `if (from == NULL) return NULL;`). MEM10-C should only fire when
 * there is real evidence of duplicated/inconsistent ad hoc checks, not on a
 * lone guard like this.
 */

char *build_dsn(char *from) {
    if (from == NULL) {
        return NULL;
    }
    return from;
}
