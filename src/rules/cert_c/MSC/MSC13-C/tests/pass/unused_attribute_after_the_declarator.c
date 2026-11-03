/*
 * Rule: MSC13-C
 * Source: custom
 * Status: PASS - Should NOT trigger MSC13-C violation
 * Description: The variable is declared unused with a GNU attribute written
 * after its declarator, a position GCC accepts and the grammar does not.
 * Once the attribute is read as the declaration's own, the declared intent
 * is honored as it is for the attribute written in front.
 */

int count(void)
{
    int spare __attribute__((unused)) = 0;
    return 1;
}
