/*
 * Rule: FIO34-C
 * Source: aurora-lint (misfire: EOF matched as a substring)
 * Status: PASS - Should NOT trigger FIO34-C violation
 *
 * A lexer loop compares its own token code TOK_EOF, whose name contains
 * the spelling "EOF". No character read from a stream is compared with the
 * EOF macro anywhere.
 */
#include <stdio.h>

enum { TOK_EOF = 256 };

int next_token(FILE *fp);

int count_tokens(FILE *fp) {
    int tok;
    int n = 0;
    while ((tok = next_token(fp)) != TOK_EOF) {
        n++;
    }
    return n;
}
