/*
 * Rule: MEM05-C
 * Source: synthetic
 * Status: FAIL - a block object that hides a file-scope typedef
 * Expect: count=1
 *
 * Inside the function, `count` is the object, though a typedef of that
 * name encloses it, so `(count) + 1` reads the object and the array is
 * variable-length.
 */
typedef unsigned count;

void sink(char *p);

void runtime_size(int n)
{
    int count = n;
    char by_object[(count) + 1];
    sink(by_object);
}
