/*
 * Rule: MSC37-C
 * Source: synthetic
 * Status: PASS under the default and strict presets; VIOLATION under pedantic
 * Expect: default=clean strict=clean pedantic=violation
 *
 * `NR` is a macro defined as the C23 `[[noreturn]]` attribute. Like the
 * C11 specifier, the standard attribute is credited through a macro under
 * every preset that trusts the keyword, whatever the value of
 * `msc37_attribute_noreturn`, which governs only the GNU attribute.
 */

#define NR [[noreturn]]

NR void die(void);

int parse(int token)
{
    if (token > 0) {
        return token;
    }
    die();
}
