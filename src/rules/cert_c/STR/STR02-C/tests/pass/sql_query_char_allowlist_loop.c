/*
 * Rule: STR02-C
 * Source: custom (CWE-89, task 470 -- hostap eap_user_db.c FP class)
 * Status: PASS - Should NOT trigger STR02-C violation
 */

int check_query(sqlite3 *db, const char *identity) {
    char id_str[256], cmd[300];
    size_t i, len;

    len = strlen(identity);
    strncpy(id_str, identity, sizeof(id_str));
    id_str[len] = '\0';

    for (i = 0; i < len; i++) {
        if (id_str[i] >= 'a' && id_str[i] <= 'z')
            continue;
        if (id_str[i] >= 'A' && id_str[i] <= 'Z')
            continue;
        if (id_str[i] >= '0' && id_str[i] <= '9')
            continue;
        return -1;
    }

    snprintf(cmd, sizeof(cmd), "SELECT * FROM users WHERE identity='%s';", id_str);
    return sqlite3_exec(db, cmd, 0, 0, 0);
}
