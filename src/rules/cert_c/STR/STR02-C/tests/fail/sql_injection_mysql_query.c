/*
 * Rule: STR02-C
 * Source: custom (CWE-89, task 8/301)
 * Status: FAIL - Should trigger STR02-C violation
 *
 * username is a function parameter (tainted by default, no caller
 * context proving it clean) built directly into the query string with
 * no escaping before mysql_query().
 */

void vulnerable_lookup(MYSQL *conn, const char *username) {
    char query[256];
    sprintf(query, "SELECT * FROM users WHERE name='%s'", username);
    mysql_query(conn, query);
}
