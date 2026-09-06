/*
 * Rule: INT30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger INT30-C violation
 *
 * Tests narrow-operand arithmetic through widening casts (task 60). When a
 * uint8_t or uint16_t value is cast to uint32_t and combined with another
 * narrow value or a small constant, the result provably fits in uint32_t.
 */

#include <stdint.h>

enum {
    HDR_TAG = 2,
    HDR_LEN = 2,
    HDR_CRC = 1,
    HDR_TOTAL = HDR_TAG + HDR_LEN + HDR_CRC
};

typedef struct {
    uint16_t length;
    uint16_t tag;
} tlv_t;

typedef struct {
    uint8_t b;
    uint8_t g;
    uint8_t r;
} rgb_t;

typedef struct {
    union {
        rgb_t components;
        uint32_t rgb;
    };
    uint8_t brightness;
} led_t;

/* (uint32_t)uint16_t + enum-constant — widened narrow plus small const */
uint32_t widened_length_plus_hdr(const tlv_t *p) {
    return (uint32_t)p->length + HDR_TOTAL;
}

/* uint16_t + uint16_t through casts — max 131070, fits uint32_t */
uint32_t widened_sum_narrow(uint16_t a, uint16_t b) {
    return (uint32_t)a + (uint32_t)b;
}

/* uint16_t * uint16_t through casts — max ~4.29e9, fits uint32_t */
uint32_t widened_product_narrow(uint16_t a, uint16_t b) {
    return (uint32_t)a * (uint32_t)b;
}

/* uint8_t * uint8_t through casts — comfortably fits */
uint32_t widened_product_byte(uint8_t a, uint8_t b) {
    return (uint32_t)a * (uint32_t)b;
}

/* Mixed: one narrow cast, other a small literal — fits uint32_t */
uint32_t widened_plus_literal(uint16_t a) {
    return (uint32_t)a + 100;
}

/* Mixed: narrow cast times small literal — fits uint32_t */
uint32_t widened_times_literal(uint16_t a) {
    return (uint32_t)a * 13;
}

/* Nested struct field (anonymous union) times uint8_t — both narrow. */
uint32_t nested_field_product(const led_t *led) {
    return (uint32_t)led->components.g * led->brightness;
}

/* `(uint32_t)(a - b) * SMALL` guarded by `if (a > b)` — pre-cast narrow */
uint32_t guarded_sub_times_scale(uint16_t a, uint16_t b) {
    if (a > b) {
        return (uint32_t)(a - b) * 13;
    }
    return 0;
}

/* `a > b + C` (C positive constant) implies a > b for guard detection */
uint32_t guarded_sub_gt_plus_margin(uint16_t a, uint16_t b) {
    if (a > b + 32) {
        return (uint32_t)(a - b) * 5;
    }
    return 0;
}

int main(void) {
    return 0;
}
