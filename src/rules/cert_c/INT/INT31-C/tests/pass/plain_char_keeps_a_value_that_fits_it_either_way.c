/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - A plain char nobody declares either way keeps a value that fits it as signed or as unsigned
 *
 * Whether plain `char` is signed is the implementation's choice, and this
 * project does not declare it. Each value stored fits one of the two
 * readings: a small negative product fits a signed `char`, and a byte
 * masked to `0xFF` fits an unsigned one.
 */

void sink(int);

void stores(unsigned long n)
{
    char data = -2;
    if (data < 0) {
        char result = data * 2;
        sink(result);
    }
    char byte = (char)(n & 0xFF);
    sink(byte);
}
