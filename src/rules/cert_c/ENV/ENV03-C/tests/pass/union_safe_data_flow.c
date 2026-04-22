/*
 * Rule: ENV03-C
 * Source: testcases (Juliet v34 pattern)
 * Status: PASS - Should NOT trigger ENV03-C violation
 *
 * Union data flow: data written to one union member and read back through
 * another (alias). If the source is a safe fixed buffer, the command arg
 * is clean even though it was routed through a union field.
 */

#ifdef _WIN32
#define SYSTEM system
#else
#define SYSTEM system
#endif

typedef union {
    char *unionFirst;
    char *unionSecond;
} UnionType;

/* goodG2B pattern: safe buffer written to union, read back through alias */
static void good_union_safe_flow(void) {
    char *data;
    UnionType myUnion;
    char data_buf[100] = "ls ";
    data = data_buf;
    /* append a fixed string — no external input */
    /* myUnion aliased to the safe buffer */
    myUnion.unionFirst = data;
    {
        char *data2 = myUnion.unionSecond;
        /* data2 is safe: same memory as data_buf */
        SYSTEM(data2);
    }
}

/* Multiple safe fields assigned before read */
static void good_union_multi_safe(void) {
    char buf1[50] = "ls";
    char buf2[50] = "dir";
    UnionType u;
    u.unionFirst = buf1;
    u.unionFirst = buf2;          /* overwrite with another safe value */
    char *cmd = u.unionSecond;
    SYSTEM(cmd);
}
