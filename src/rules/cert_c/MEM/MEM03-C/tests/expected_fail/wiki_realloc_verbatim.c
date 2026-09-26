/*
 * Rule: MEM03-C
 * Source: wiki, CERT MEM03-C "Noncompliant Code Example ( `realloc()` )", verbatim
 * Status: EXPECTED_FAIL - CERT's own noncompliant example, not detected yet
 *
 * CERT's realloc() noncompliant example as written: realloc() may move the
 * secret and leave the old copy uncleared. The call sits in the else branch
 * of the size check.
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
