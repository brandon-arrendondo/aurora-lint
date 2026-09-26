/*
 * Rule: EXP19-C
 * Source: testcases
 * Status: FAIL - a block macro invoked with its semicolon is, as written, a
 * single unbraced statement in the for body
 */

typedef struct { int marked; } Obj;

#define markobject(o) { if (!(o)->marked) (o)->marked = 1; }

void mark_all(Obj *objs, int n) {
    int i;
    for (i = 0; i < n; i++)
        markobject(&objs[i]);
}
