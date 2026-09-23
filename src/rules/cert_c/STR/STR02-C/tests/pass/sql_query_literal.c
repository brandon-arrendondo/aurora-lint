/*
 * Rule: STR02-C
 * Source: custom (CWE-89)
 * Status: PASS - Should NOT trigger STR02-C violation
 */

sqlite3_exec(db, "SELECT * FROM users", 0, 0, &errmsg);
