/*
 * Rule: MEM03-C
 * Source: wiki, CERT MEM03-C "Noncompliant Code Example (realloc())", verbatim
 * Status: EXPECTED_FAIL - CERT's own noncompliant example, not detected yet
 *
 * realloc() may move the secret and leave the old copy uncleared. The
 * expected report is that realloc one.
 *
 * CERT's fragment is not a complete translation unit: its statements sit at
 * file scope, the rule sees them through a parse error, and that is why it
 * reports nothing here. The same text wrapped in a function is reported,
 * but only with MEM03-C's unrelated "not cleared before function exit"
 * message; the realloc in the else arm is still missed. The fixture harness
 * checks the rule id, not the message or line, so a wrapped copy would pass
 * for the wrong reason, and this file is kept verbatim instead.
 *
 * Under MEM03-C's target design a buffer's sensitivity is declared, not
 * read from its name, so CERT's name-only `secret` is reported only when
 * the scan declares it sensitive.
 */

char *secret;

/* Initialize secret */

size_t secret_size = strlen(secret);
/* ... */
if (secret_size > SIZE_MAX/2) {
   /* Handle error condition */
}
else {
secret = (char *)realloc(secret, secret_size * 2);
}
