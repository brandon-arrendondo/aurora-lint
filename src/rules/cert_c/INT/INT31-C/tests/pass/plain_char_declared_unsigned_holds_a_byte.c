/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - A plain char the project declares unsigned holds every byte value
 * Settings: data_model=lp64, char_signed=false
 *
 * The project declares plain `char` unsigned, so it holds 0 to 255: a byte
 * masked to `0xFF` and the constant 200 both fit.
 */

void sink(int);

void stores(unsigned long n)
{
    char byte = (char)(n & 0xFF);
    char high = 200;
    sink(byte + high);
}
