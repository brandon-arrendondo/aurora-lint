/*
 * Rule: INT02-C
 * Source: regression
 * Status: FAIL - a full-width `unsigned` bit-field compared with an int
 *
 * A bit-field as wide as int keeps its declared type, `unsigned int`, so
 * the signed operand is converted to unsigned: a negative `limit` compares
 * greater than any flag word.
 */

struct word {
    unsigned bits : 32;
};

int below(struct word *w, int limit)
{
    return w->bits < limit;
}
