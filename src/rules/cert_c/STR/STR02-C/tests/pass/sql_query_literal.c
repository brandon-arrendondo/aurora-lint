/*
 * Rule: STR02-C
 * Source: custom (CWE-89, task 8/301)
 * Status: PASS - Should NOT trigger STR02-C violation
 */

sqlite3_exec(db, "SELECT * FROM users", 0, 0, &errmsg);
