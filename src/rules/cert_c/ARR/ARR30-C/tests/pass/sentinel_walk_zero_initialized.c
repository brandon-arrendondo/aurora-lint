/*
 * Rule: ARR30-C
 * Source: task 1021 (NUL-sentinel walk over a fixed-size char array)
 * Status: PASS - Should NOT trigger ARR30-C violation
 * Reason: raylib's ExportXAsCode() idiom. The walk is bounded by the array's
 * own terminator rather than by a relational test, so every comparison-based
 * channel sees a variable index never compared against the size. It is
 * bounded all the same: the body only runs for an `i` the condition just read
 * as non-NUL, and the zero-initializer plus a strncpy capped at 256 - 1 leave
 * the last byte NUL, so that terminator is inside the array.
 */

#include <string.h>

const char *GetFileNameWithoutExt(const char *fileName);

void ExportDataAsCode(const char *fileName)
{
    char varFileName[256] = { 0 };
    strncpy(varFileName, GetFileNameWithoutExt(fileName), 256 - 1);
    for (int i = 0; varFileName[i] != '\0'; i++)
    {
        if ((varFileName[i] >= 'a') && (varFileName[i] <= 'z')) varFileName[i] = varFileName[i] - 32;
    }
}
