/*
 * Rule: STR02-C
 * Source: custom (CWE-89, task 8/301)
 * Status: FAIL - Should trigger STR02-C violation
 */

char query[256];
sprintf(query, "SELECT * FROM users WHERE name='%s'", username);
sqlite3_exec(db, query, 0, 0, &errmsg);
