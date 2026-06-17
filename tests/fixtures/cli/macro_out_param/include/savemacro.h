/* A CF_DATA_SAVE-style output macro, mirroring curl's
 * lib/cfilters.h CF_DATA_SAVE(save, cf, data). The macro body *assigns* its
 * first parameter ((save) = ...), so that parameter is a macro OUTPUT argument:
 * a bare identifier passed there is written by the macro, not read. Only the
 * macro-expansion engine (ProjectContext.function_macros +
 * macro_output_param_indices) lets EXP33-C see that, so reads of the variable
 * are not "used uninitialized" false positives (task 185, Phase 2c-ii). */
#ifndef SAVEMACRO_H
#define SAVEMACRO_H

#define DATA_SAVE(save, ctx)    do { (save) = (ctx)->saved; } while(0)
#define DATA_RESTORE(ctx, save) do { (ctx)->saved = (save); } while(0)

#endif
