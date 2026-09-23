/*
 * Rule: INT16-C
 * Source: custom
 * Status: PASS - should NOT trigger INT16-C violation
 * Description: The two real-world shapes behind aurora_lint an earlier fix, where
 * 10 of 10 fresh raylib+sqlite findings claimed a signed/unsigned mismatch
 * that the declarations do not contain. Both were produced by the
 * file-wide name map `099e40d5` retired; both are answered here by
 * resolving the occurrence to its declaration. The `< 0` guards exist so
 * VRA has the negative evidence the rule demands of a source -- without
 * them neither version reports anything and the fixture pins nothing.
 *
 * 1. The destination is a field reached through a TYPEDEF'D struct pointer
 *    (`Image *image`, not `struct Image *image`), and the field is a plain
 *    `int`. raylib's `image->width = newWidth`, `bones[i].parent =
 *    parentIndex` and `batch.bufferCount = numBuffers` were all reported
 *    because `image->width` as text was absent from a signed-name map, and
 *    absence was read as "potentially unsigned". A destination is unsigned
 *    only when its declared type says so.
 *
 * 2. The source is a local whose type is a TYPEDEF for an unsigned integer
 *    (`u32 nPage`), and the same NAME is declared `int` in another function
 *    of the file. sqlite's btree.c `pBt->nPage = nPage` (u32 into u32) was
 *    reported as a signed source because the unrelated `int nPage` had put
 *    the name in the map. The source's sign comes from the declaration in
 *    scope at the assignment, so u32 -> u32 is not a conversion at all.
 */

typedef unsigned int u32;

typedef struct Image {
    void *data;
    int width;
    int height;
} Image;

typedef struct BoneInfo {
    char name[32];
    int parent;
} BoneInfo;

typedef struct BtShared {
    u32 nPage;
    u32 pageSize;
} BtShared;

void resize_canvas(Image *image, int newWidth) {
    if (newWidth < 0) {
        image->width = newWidth;
    }
}

void link_bones(BoneInfo *bones, int count, int parentIndex) {
    int i;
    if (parentIndex < 0) {
        for (i = 0; i < count; i++) {
            bones[i].parent = parentIndex;
        }
    }
}

int count_pages(int nPage) {
    int total = 0;
    if (nPage < 0) {
        total = nPage;
    }
    return total;
}

void lock_btree(BtShared *pBt, int n) {
    u32 nPage = 0;
    if (n < 0) {
        nPage = (u32)n;
    }
    pBt->nPage = nPage;
    pBt->pageSize = nPage;
}
