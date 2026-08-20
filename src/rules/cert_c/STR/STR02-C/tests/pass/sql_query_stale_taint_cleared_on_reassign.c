/*
 * Rule: STR02-C
 * Source: custom (CWE-89, task 470 -- hostap eap_user_db.c FP class)
 * Status: PASS - Should NOT trigger STR02-C violation
 */

int lookup(sqlite3 *db, const char *identity) {
    char cmd[300];

    /* Builds a tainted query, but it's never passed to a sink here. */
    snprintf(cmd, sizeof(cmd), "SELECT * FROM users WHERE identity='%s';", identity);

    /* cmd is fully overwritten with a fixed query -- no taint should survive. */
    snprintf(cmd, sizeof(cmd), "SELECT identity,methods FROM wildcards;");
    return sqlite3_exec(db, cmd, 0, 0, 0);
}
