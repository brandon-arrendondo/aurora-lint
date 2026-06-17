/* `save` is declared uninitialized, then written by the DATA_SAVE output macro
 * (defined in include/savemacro.h) and read back by DATA_RESTORE. Without the
 * macro-output-arg recognition, EXP33-C flags `save` as "used uninitialized"
 * both at the DATA_SAVE call (its output position) and at the DATA_RESTORE read
 * — the curl CF_DATA_SAVE false-positive class (task 185, Phase 2c-ii). */
#include "savemacro.h"

struct ctx {
    int saved;
};

void run(struct ctx *c) {
    int save;

    DATA_SAVE(save, c);
    DATA_RESTORE(c, save);
}
