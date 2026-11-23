/*
 * Rule: ARR32-C
 * Source: synthetic
 * Status: PASS - An enumerator in an inner block hides an outer object
 *
 * A name means what its innermost declaration in scope makes it (C11
 * 6.2.1p4). Inside the block, `slots` is the enumerator, though the
 * parameter of the same name encloses it, so the array is not
 * variable-length.
 */
void sink(char *p);

void fixed_size(int slots)
{
    {
        enum { slots = 4 };
        char by_enumerator[slots + 1];
        sink(by_enumerator);
    }
}
