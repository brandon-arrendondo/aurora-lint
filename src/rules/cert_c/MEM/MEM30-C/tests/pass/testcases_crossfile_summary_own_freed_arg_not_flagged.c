// sqc-test: prescan
/*
 * Rule: MEM30-C
 * Source: hostap ground-truth audit (task 159 wave 30) / task 400
 * Status: PASS - Should NOT trigger MEM30-C violation on 'h->conn'
 *
 * Regression: mirrors hostap's tls_connection_deinit(ssl_ctx, conn). Once
 * the cross-file FunctionSummary attributes the free to the 'conn'
 * argument, that same argument's own occurrence in the call expression
 * (here a field access, h->conn) must not be re-walked and flagged as
 * "accessing freed memory" at the free call's own line -- passing a
 * pointer to be freed is not itself a use-after-free.
 */

struct conn_holder { void *conn; };

static void tls_connection_deinit(void *ssl_ctx, void *conn)
{
	free(conn);
}

void caller(void *ssl_ctx, struct conn_holder *h)
{
	tls_connection_deinit(ssl_ctx, h->conn);
}
