/*
 * Rule: MSC12-C
 * Status: PASS - a counting loop whose whole purpose is the induction
 *         variable it leaves behind. The condition scans a table to its
 *         sentinel and the update advances; the body has nothing to do
 *         (mosquitto's websockets.c counts its protocol table this way).
 *
 * fail/testcases_empty_for_body.c is the boundary: `for(i=0; i<10; i++) {}`
 * reads nothing through indirection, so it really does nothing and is
 * still reported.
 */

struct entry { const char *name; };

int count_entries(const struct entry *entries)
{
    int n;
    for (n = 0; entries[n].name; n++) {
        ;
    }
    return n;
}
