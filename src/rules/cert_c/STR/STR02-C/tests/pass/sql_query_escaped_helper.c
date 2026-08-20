/*
 * Rule: STR02-C
 * Source: custom (CWE-89, task 8/301)
 * Status: PASS - Should NOT trigger STR02-C violation
 *
 * Mirrors pure-ftpd's log_mysql.c/log_pgsql.c pattern (task 301): the raw
 * tainted parameter is passed through a project-local escaping helper
 * first, and only the escaped result feeds the query. mysql_escape_string
 * is not in STR02-C's own TAINT_PROPAGATORS list, so `escaped` is never
 * marked tainted -- the same conservative "unknown function contributes no
 * taint" default that already lets STR02-C leave escaped SQL construction
 * alone (see check_sinks' TAINT_PROPAGATORS docs).
 */

void safe_lookup(MYSQL *conn, const char *username) {
    char query[256];
    char *escaped = mysql_escape_string_wrapper(conn, username);
    sprintf(query, "SELECT * FROM users WHERE name='%s'", escaped);
    mysql_query(conn, query);
}
