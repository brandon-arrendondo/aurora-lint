/*
 * Rule: MEM30-C
 * Source: real-world (sqlite: fts3Appendf(pRc, &zRet, ...) frees and
 *         replaces the string only while *pRc is SQLITE_OK)
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Description: `append` releases `*buf` and stores a fresh block in its
 * place, and only while no error has been recorded. After the call the
 * caller's pointer names a live block, or the one it had. Reusing it,
 * handing it back and freeing it once are all sound.
 */
#include <stdlib.h>
#include <string.h>

static void append(int *rc, char **buf, const char *text)
{
    if (*rc == 0) {
        size_t old = *buf ? strlen(*buf) : 0;
        char *grown = malloc(old + strlen(text) + 1);
        if (grown == NULL) {
            *rc = 1;
            return;
        }
        grown[0] = '\0';
        if (*buf)
            strcpy(grown, *buf);
        strcat(grown, text);
        free(*buf);
        *buf = grown;
    }
}

char *build(int *rc)
{
    char *out = NULL;
    append(rc, &out, "docid");
    append(rc, &out, ", x");
    return out;
}

void build_and_drop(void)
{
    int rc = 0;
    char *out = NULL;
    append(&rc, &out, "rowid");
    if (rc == 0)
        out[0] = 'R';
    free(out);
}
