/*
 * Rule: ARR30-C
 * Source: task 1021 (NUL-sentinel walk over a fixed-size char array)
 * Status: FAIL - SHOULD trigger ARR30-C violation
 * Reason: the counterexample that keeps the sentinel-walk proof honest. The
 * walk looks identical to tests/pass/sentinel_walk_zero_initialized.c, but
 * nothing puts a NUL inside the array: no zero-initializer, and a memcpy
 * filling all 64 bytes carries no terminator. The walk therefore runs off the
 * end, so the terminator bound proves nothing here.
 */

#include <string.h>

void ScanRaw(const char *src)
{
    char buf[64];
    memcpy(buf, src, 64);
    for (int i = 0; buf[i] != '\0'; i++)
    {
        if (buf[i] == '/') buf[i] = '_';
    }
}
