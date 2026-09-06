/*
 * Rule: MSC13-C
 * Status: PASS - the variable IS read, inside a macro body aurora-lint does not
 * expand. A macro is textual substitution, so a free identifier in its
 * replacement list binds to whatever that name means at the call site --
 * here `IdChar(...)` both writes and reads the caller's `c`, and the name
 * never appears at the call site for an identifier walk to find.
 *
 * Reduced from sqlite src/complete.c (task 756). `IdChar` is defined twice
 * under mutually exclusive guards and only the second definition mentions
 * `c`, so the check has to consult every preprocessor alternative of a
 * macro name rather than whichever one an expander would have picked.
 */

#define SQLITE_EBCDIC 1

extern const char sqlite3CtypeMap[];
extern const char sqlite3IsEbcdicIdChar[];

#ifdef SQLITE_ASCII
#define IdChar(C)  ((sqlite3CtypeMap[(unsigned char)C]&0x46)!=0)
#endif
#ifdef SQLITE_EBCDIC
#define IdChar(C)  (((c=C)>=0x42 && sqlite3IsEbcdicIdChar[c-0x40]))
#endif

int scan_identifier(const char *zSql)
{
#ifdef SQLITE_EBCDIC
    unsigned char c;
#endif
    int nId = 0;
    if( IdChar((unsigned char)*zSql) ){
        for(nId=1; IdChar(zSql[nId]); nId++){}
    }
    return nId;
}
