/*
 * Rule: EXP36-C
 * Source: task 736 (sqlite delta-adjudication of run 228)
 * Status: PASS - Should NOT trigger EXP36-C violation
 */

/*
 * Reason: sqlite defines `typedef long long int sqlite_int64;` then
 * `typedef sqlite_int64 i64;`, so `i64` has size 8 and alignment 8. The
 * cast `(u64*)&x` where `x` is `i64` is a same-width signed<->unsigned
 * pointer conversion with IDENTICAL alignment. Before the shared
 * typedef-chain resolver, EXP36-C's alignment table exact-matched
 * "i64 *", missed, fell through to the "unknown pointer -> assume 4-byte"
 * default and fabricated a 4->8 alignment jump on every varint reader.
 * 15 labeled sqlite FPs across two adjudication passes had this shape
 * (ext/fts5/fts5_index.c:4340/4341/4590/5988/8581/8892/8903;
 * src/btree.c:5887; older ext/fts3/fts3.c:358-360/422-424;
 * ext/fts5/fts5_tcl.c:641).
 */

typedef long long int sqlite_int64;
typedef sqlite_int64 i64;
typedef unsigned long long u64;

int read_varint(u64 *v);

int process(i64 x)
{
    return read_varint((u64 *)&x);
}

int process_two_hops(sqlite_int64 y)
{
    return read_varint((u64 *)&y);
}
