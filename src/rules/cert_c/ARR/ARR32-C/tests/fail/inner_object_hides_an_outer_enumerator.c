/*
 * Rule: ARR32-C
 * Source: synthetic
 * Status: FAIL - An object in an inner block hides an outer enumerator
 * Expect: count=1
 *
 * Inside the block, `slots` is the object, though an enumerator of the
 * same name encloses it, so the size reads an object and the array is
 * variable-length.
 */
enum { slots = 4 };

void sink(char *p);

void runtime_size(int len)
{
    {
        int slots = len;
        char by_object[slots + 1];
        sink(by_object);
    }
}
