/*
 * Rule: INT33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger INT33-C violation
 */

/*
 * Rule: INT33-C - Ensure that division and remainder operations do not result in divide-by-zero errors
 * Status: PASS
 * Reason: Divisor is a compile-time constant macro with a known non-zero value
 */

#include <stdint.h>

#define BRIGHTNESS_MAX 255
#define SCALE_FACTOR 100
#define PERIOD_MS 20

static uint8_t scale_color(uint8_t color, uint8_t brightness)
{
    /* BRIGHTNESS_MAX = 255 — provably non-zero, no divide-by-zero risk */
    return (uint8_t)(((uint32_t)color * brightness) / BRIGHTNESS_MAX);
}

static int percent(int value, int total)
{
    /* SCALE_FACTOR = 100 — provably non-zero */
    return (value * SCALE_FACTOR) / SCALE_FACTOR;
    (void)total;
}

static int period_ticks(int freq_hz)
{
    /* PERIOD_MS = 20 — provably non-zero */
    return freq_hz / PERIOD_MS;
}
