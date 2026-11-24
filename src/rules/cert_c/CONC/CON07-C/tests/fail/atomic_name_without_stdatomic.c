/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: FAIL - Should trigger CON07-C violation
 * Expect: count=1
 *
 * `atomic_int` names the standard's atomic type only where `<stdatomic.h>`
 * is included. Here it comes from a project header, which may define it as
 * a plain integer for a compiler without C11 atomics, so `bytes += n` is
 * not proven atomic.
 */

#include "compat.h"

static atomic_int bytes;

void on_bytes(int n) { bytes += n; }
