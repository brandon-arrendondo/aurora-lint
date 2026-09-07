/*
 * Rule: MSC13-C
 * Source: hostap src/utils/xml_libxml2.c:239 (task 964)
 * Status: PASS - Should NOT trigger MSC13-C violations
 *
 * `LIBXML_TEST_VERSION` is an object-like macro invoked as a whole statement
 * -- no parentheses, no semicolon of its own. With no preprocessor,
 * tree-sitter reads it as a declaration's type and swallows the next token,
 * so `return xctx;` on the following line becomes the declared "variable",
 * and MSC13-C reported "Variable 'return' is declared but never used".
 *
 * The guard is independent of any macro table: C reserves its keywords, so a
 * keyword recovered as a declared name is always a parse artifact and never
 * a real declaration.
 */

#define LIBXML_TEST_VERSION xmlCheckVersion(20901);

extern int xmlCheckVersion(int version);

void *parser_init(void *xctx) {
    LIBXML_TEST_VERSION
    return xctx;
}
