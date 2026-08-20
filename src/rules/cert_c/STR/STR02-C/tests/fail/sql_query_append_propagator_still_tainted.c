/*
 * Rule: STR02-C
 * Source: custom (CWE-89, task 470 -- append-style propagators like
 *   strncat must NOT clear dest's taint the way an overwrite like
 *   snprintf does, since they layer onto existing content rather than
 *   replacing it)
 * Status: FAIL - Should trigger STR02-C violation
 */

int build(sqlite3 *db, const char *identity) {
    char cmd[300];

    snprintf(cmd, sizeof(cmd), "SELECT * FROM users WHERE identity='");
    strncat(cmd, identity, sizeof(cmd) - strlen(cmd) - 1);
    strncat(cmd, "';", sizeof(cmd) - strlen(cmd) - 1);
    return sqlite3_exec(db, cmd, 0, 0, 0);
}
