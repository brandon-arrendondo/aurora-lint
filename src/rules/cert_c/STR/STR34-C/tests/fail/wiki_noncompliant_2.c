/*
 * Rule: STR34-C
 * Source: wiki
 * Status: FAIL - Should trigger STR34-C violation. c_str must be plain
 * "char *" (signed, matching the real bash CVE this example is drawn
 * from) for the sign-extension bug to exist; the fixture previously had
 * "unsigned char *" here, a scraper transcription error that made
 * *c_str already unsigned and the code genuinely compliant as written.
 * Verified against the live wiki (search-indexed, direct fetch 404s):
 * noncompliant AND compliant both declare "register char *c_str;" --
 * the fix is the (unsigned char) cast on the read, not the pointer type.
 */

static int yy_string_get(void) {
  register char *c_str;
  register int c;

  c_str = bash_input.location.string;
  c = EOF;

  /* If the string doesn't exist or is empty, EOF found */
  if (c_str && *c_str) {
    c = *c_str++;
    bash_input.location.string = c_str;
  }
  return (c);
}