/*
 * Rule: STR02-C
 * Source: custom (CWE-89, task 470 -- char-allowlist-loop validation must
 *   require the loop to actually deny by default; a loop whose body never
 *   exits early is not a validation guard and must stay conservative)
 * Status: FAIL - Should trigger STR02-C violation
 */

int lookup(sqlite3 *db, const char *identity) {
    char cmd[300];
    size_t i;

    for (i = 0; identity[i] != '\0'; i++) {
        if (identity[i] == '\'')
            continue;
    }

    snprintf(cmd, sizeof(cmd), "SELECT * FROM users WHERE identity='%s';", identity);
    return sqlite3_exec(db, cmd, 0, 0, 0);
}
