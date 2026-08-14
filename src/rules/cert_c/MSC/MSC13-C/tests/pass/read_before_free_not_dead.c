/*
 * Rule: MSC13-C
 * Status: PASS - Should NOT trigger MSC13-C violation
 */

/*
 * Reason (task 391, hostap's rfkill.c): `rfk_phy` genuinely is read (as a
 * call argument to `os_strcmp`) before being freed. The shared
 * reaching-definitions dataflow also emits a synthetic `FreeCall`
 * pseudo-definition at the `free(rfk_phy)` call site for MEM30-C/MEM31-C's
 * benefit; MSC13-C previously treated that pseudo-definition like a real
 * value-producing write requiring its own subsequent read, so it flagged
 * the free() call itself as an unread dead store even though the variable's
 * one real assignment was already read.
 */

int os_strcmp(const char *a, const char *b);
char *realpath(const char *path, char *resolved);
void free(void *p);

void foo(char *phy)
{
    char *rfk_phy;
    int found;

    rfk_phy = realpath("x", 0);
    if (!rfk_phy)
        return;
    found = os_strcmp(phy, rfk_phy) == 0;
    free(rfk_phy);
    (void)found;
}
