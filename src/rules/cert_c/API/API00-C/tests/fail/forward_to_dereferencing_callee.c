/*
 * Rule: API00-C
 * Source: custom
 * Status: FAIL - SHOULD trigger API00-C violation
 * Description: The true-positive twin of tests/pass/
 * pointer_stored_or_relayed_is_not_a_dereference.c, and the exact
 * counterexample task 744's adjudication recorded: at the flagged function a
 * safe forwarding wrapper and an unsafe one are structurally IDENTICAL, so
 * only the callee's body separates them.
 *
 * decrypt_body dereferences its argument at `if (conn->client)` and null-tests
 * it only afterwards, which is not a guard for anything the caller hands in.
 * A forward-implies-safe shortcut would turn this confirmed true positive
 * into a miss.
 */

struct conn {
    int client;
};

int decrypt_body(struct conn *conn)
{
    if (conn->client)
        return 1;
    if (!conn)
        return -1;
    return 0;
}

int tls_connection_decrypt(struct conn *conn)
{
    return decrypt_body(conn);
}
