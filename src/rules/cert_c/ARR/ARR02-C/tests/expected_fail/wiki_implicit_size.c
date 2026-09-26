/*
 * Rule: ARR02-C
 * Source: wiki, CERT ARR02-C "Noncompliant Code Example (Implicit Size)", verbatim
 * Status: EXPECTED_FAIL - CERT's own noncompliant example, not detected yet
 *
 * CERT: "Explicitly specify array bounds, even if implicitly defined by an
 * initializer". This array's bound comes only from its initializer, which is
 * the construct the guideline names. The rule currently skips any bound-less
 * declarator that has an initializer, so this example goes unreported. It
 * returns to tests/fail/ when the implicit-size form is detected again.
 */

int a[] = {1, 2, 3, 4};
