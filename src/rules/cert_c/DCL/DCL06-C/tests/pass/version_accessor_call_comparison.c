/*
 * Rule: DCL06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger DCL06-C violation
 */

/*
 * Rule: DCL06-C - Use meaningful symbolic constants
 * Status: PASS
 * Reason: A version check spelled as a version-accessor CALL is the same
 *         idiom the version-macro exemption already covers for a bare
 *         identifier: sqlite's `sqlite3_libversion_number() >= 3008002`,
 *         curl's `Curl_conn_http_version(data, conn) != 20`. Task 1153,
 *         mechanism 4.
 */

int sqlite3_libversion_number(void);
int conn_http_version(void *conn);

int supports_feature(void *conn)
{
    if (sqlite3_libversion_number() >= 3008002) {
        return 1;
    }
    if (conn_http_version(conn) != 20) {
        return 0;
    }
    return 0;
}
