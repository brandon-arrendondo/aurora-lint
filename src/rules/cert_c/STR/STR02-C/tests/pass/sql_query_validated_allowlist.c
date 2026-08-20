/*
 * Rule: STR02-C
 * Source: custom (CWE-89, task 8/301)
 * Status: PASS - Should NOT trigger STR02-C violation
 *
 * Mirrors a real pattern found on hostap's src/eap_server/eap_sim_db.c
 * (task 8): the tainted parameter is validated against a character
 * allow-list, with an early exit on failure, before being snprintf'd
 * into the query buffer.
 */

static int valid_db_string(const char *str) {
    const char *pos = str;
    while (*pos) {
        if ((*pos < '0' || *pos > '9') && (*pos < 'a' || *pos > 'f'))
            return 0;
        pos++;
    }
    return 1;
}

static char *db_get_pseudonym(sqlite3 *db, const char *pseudonym) {
    char cmd[128];

    if (!valid_db_string(pseudonym))
        return NULL;
    sprintf(cmd, "SELECT permanent FROM pseudonyms WHERE pseudonym='%s';", pseudonym);
    if (sqlite3_exec(db, cmd, NULL, NULL, NULL) != 0)
        return NULL;
    return NULL;
}
