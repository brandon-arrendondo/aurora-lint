/*
 * Rule: ARR30-C
 * Source: real-world
 * Status: FAIL - `res < sizeof(arr)` on `int arr[32]` proves `res < 128`,
 *         not `res < 32`; three quarters of that range is out of bounds.
 *
 * `sizeof` of the array being indexed is its BYTE size and bounds an element
 * index only when an element is a byte. The early-return proof declines
 * anything wider, so this is the byte-width twin of the PASS fixture's
 * `char` buffers.
 */

int rd(void);

int fill(void)
{
    int arr[32];
    int res = rd();

    if (res < 0 || (size_t) res >= sizeof(arr))
        return -1;
    arr[res] = 0;
    return 0;
}
