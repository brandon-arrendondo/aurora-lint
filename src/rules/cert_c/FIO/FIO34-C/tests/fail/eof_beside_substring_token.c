/*
 * Rule: FIO34-C
 * Source: aurora-lint
 * Status: FAIL - getc() is compared with EOF and never checked with
 * feof()/ferror()
 *
 * Beside a lexer loop on its own TOK_EOF code, a second loop reads
 * characters until EOF.
 */
#include <stdio.h>

enum { TOK_EOF = 256 };

int next_token(FILE *fp);

int count_tokens(FILE *fp) {
    int tok;
    int c;
    int n = 0;
    while ((tok = next_token(fp)) != TOK_EOF) {
        n++;
    }
    while ((c = getc(fp)) != EOF) {
        n++;
    }
    return n;
}
