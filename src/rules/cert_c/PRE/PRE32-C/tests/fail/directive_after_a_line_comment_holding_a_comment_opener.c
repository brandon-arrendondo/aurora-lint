/*
 * Rule: PRE32-C
 * Source: custom
 * Status: FAIL - Should trigger PRE32-C violation
 * Description: A `//` comment holding a `/*` stands before a directive in a
 * call's argument list. That `/*` is comment text and opens nothing, so the
 * line after it is a directive. It is the only one in the arguments, and the
 * rule reports the call and the argument it stands in.
 * Expect: count=2
 */

extern int printf(const char *fmt, ...);

void dump(int i, int irq)
{
    printf("%d %d\n",
           i, // see /* the note in the header
#undef LOCAL_FLAG
           irq);
}
