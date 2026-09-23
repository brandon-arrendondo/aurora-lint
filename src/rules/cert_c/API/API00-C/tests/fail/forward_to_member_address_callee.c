/*
 * Rule: API00-C
 * Source: custom
 * Status: FAIL - SHOULD trigger API00-C violation
 * Description: A forwarder whose callee reaches the parameter only as a
 * member address. conn_meta_get never reads conn itself; it
 * hands &conn->meta to a helper that reads through it. Forming that address
 * from a null conn is already undefined, and the helper's read lands at a
 * small offset from null, so conn is used unvalidated all the same.
 *
 * The summary rightly stopped counting `&param->field` as a READ, the
 * question EXP33-C and MEM01-C ask. API00-C asks a different one -- is the
 * pointer used at all -- and borrowing the read-only test dropped every
 * forwarder of this shape. Both callees are static so neither is itself
 * reported; the only finding this file can produce is the forwarder's.
 */

struct meta {
    int count;
};

struct conn {
    struct meta meta;
};

static int meta_count(const struct meta *m)
{
    if (!m)
        return 0;
    return m->count;
}

static int conn_meta_get(struct conn *conn)
{
    return meta_count(&conn->meta);
}

int conn_has_meta(struct conn *conn)
{
    return conn_meta_get(conn) != 0;
}
