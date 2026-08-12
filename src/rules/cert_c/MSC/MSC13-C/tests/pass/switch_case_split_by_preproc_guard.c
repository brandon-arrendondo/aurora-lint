/*
 * Rule: MSC13-C
 * Status: PASS - a switch's case arms individually wrapped in `#if`/`#endif`
 * guards (raylib's per-codec `UpdateMusicStream` idiom) must still be visited
 * by the CFG. Before task 445's fix, `process_switch` only matched direct
 * `case_statement` children of the switch body -- a case arm wrapped in
 * `#if`/`#endif` was invisible, so writes/reads inside it were never modeled
 * and looked like dead stores.
 */

#define SUPPORT_FILEFORMAT_WAV 1
#define SUPPORT_FILEFORMAT_OGG 1
#define SUPPORT_FILEFORMAT_MP3 1

void UpdateMusicStream(int ctxType, int framesToStream)
{
    int frameCountStillNeeded = framesToStream;
    int frameCountReadTotal = 0;

    switch (ctxType)
    {
    #if SUPPORT_FILEFORMAT_WAV
        case 1:
        {
            while (1)
            {
                frameCountReadTotal += frameCountStillNeeded;
                frameCountStillNeeded -= frameCountReadTotal;
                if (frameCountStillNeeded == 0) break;
            }
        } break;
    #endif
    #if SUPPORT_FILEFORMAT_OGG
        case 2:
        {
            frameCountReadTotal += frameCountStillNeeded;
        } break;
    #endif
    #if SUPPORT_FILEFORMAT_MP3
        case 3:
        {
            frameCountReadTotal += frameCountStillNeeded;
        } break;
    #endif
        default:
            break;
    }

    (void)frameCountReadTotal;
}
