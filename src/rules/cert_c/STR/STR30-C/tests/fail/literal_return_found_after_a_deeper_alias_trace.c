/*
 * Rule: STR30-C
 * Source: custom
 * Status: FAIL - Should trigger STR30-C violation
 * Description: F returns a string literal behind ten parentheses, and z's
 * write goes into it. The writes through p1 and p2 ask first whether v may
 * hold a literal; v's answer that it does, found with depth to spare, is
 * reused when z's question reaches the same point with more depth left, so
 * z's write is found whatever the walk order. Before, the answer depended on
 * which question came first, and with p2's lines present z's was cut short.
 */

char *v;
char *F(void) { return (((((((((("lit")))))))))); }
void s1(void) { v = (F()); }
void s2(void) { v = "x"; }
void w(void) {
    char *t = v;
    char *p1 = ((((((((((t))))))))));
    p1[0] = 0;
    char *p2 = t;
    p2[0] = 0;
    char *z = F();
    z[0] = 0;
}
