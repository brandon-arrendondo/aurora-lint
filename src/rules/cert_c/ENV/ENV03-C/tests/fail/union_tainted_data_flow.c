/*
 * Rule: ENV03-C
 * Source: testcases (Juliet v34 bad pattern)
 * Status: FAIL - Should trigger ENV03-C violation
 *
 * Union data flow: tainted data (from getenv) written to one union member
 * and read back through another alias. The tainted value reaches system().
 */

#define SYSTEM system
#define GETENV getenv

typedef union {
    char *unionFirst;
    char *unionSecond;
} UnionType;

/* bad pattern: tainted env var written to union, read through alias */
void bad_union_tainted_flow(void) {
    char *data;
    UnionType myUnion;
    char data_buf[100] = "ls ";
    data = data_buf;
    /* FLAW: tainted data appended to buf via GETENV (macro for getenv) */
    char *env = GETENV("ADD");
    if (env != 0) {
        data = env;  /* now data is tainted */
    }
    myUnion.unionFirst = data;
    {
        char *data2 = myUnion.unionSecond;
        /* POTENTIAL FLAW: tainted data reaches system() through union alias */
        SYSTEM(data2);
    }
}
