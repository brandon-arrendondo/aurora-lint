/*
 * Rule: ARR30-C
 * Source: task 912 (sqlite ext/fts5/fts5_index.c:3705, src/where.c:1368)
 * Status: PASS - Should NOT trigger ARR30-C violation
 * Reason: the flexible-array-member check ignored the member it was asked
 *         about and returned the line of ANY while loop with ++/-- in its
 *         condition. Asked once per flexible-array struct in the file, one
 *         unrelated varint skip (`while( *p++ & 0x80 );`) produced a finding
 *         for every struct, all at that same line, each naming a struct and
 *         member the line never mentions.
 */

#define FLEXARRAY 1

typedef struct Fts5StructureLevel { int nSeg; } Fts5StructureLevel;

struct Fts5Structure {
    int nRef;
    int nLevel;
    Fts5StructureLevel aLevel[FLEXARRAY];
};

struct Fts5TombstoneArray {
    int nTombstone;
    void *apTombstone[FLEXARRAY];
};

/* An unrelated varint skip. Touches neither aLevel nor apTombstone. */
void skip_varint(unsigned char *p, unsigned char *pEnd) {
    while (p < pEnd && *p != 0x01) {
        while (*p++ & 0x80)
            ;
    }
}
