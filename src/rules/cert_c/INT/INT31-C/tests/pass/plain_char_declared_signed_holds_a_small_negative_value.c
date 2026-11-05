/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - A plain char the project declares signed holds a small negative value
 * Settings: data_model=lp64, char_signed=true
 *
 * The project declares plain `char` signed, so it holds -128 to 127: the
 * product of -2 and 2 and the constant -100 both fit.
 */

void sink(int);

void stores(void)
{
    char data = -2;
    if (data < 0) {
        char result = data * 2;
        sink(result);
    }
    char low = -100;
    sink(low);
}
