/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM30-C violation
 *
 * File-scope static arrays have static storage duration (.bss) — their addresses
 * are permanently valid. Writing scalar values to their elements via subscript
 * (arr[i] = val) is NOT a stack pointer escape and must not be flagged.
 *
 * Mirrors FP-001 patterns from Catapult RC624 firmware review.
 */

#include <stdint.h>
#include <string.h>

#define WIFI_ID_MAX   8
#define ADC_BUF_SIZE  16
#define CMD_BUF_SIZE  256

/* File-scope statics — static storage duration, live for program lifetime */
static uint8_t  dev_info[WIFI_ID_MAX];
static uint16_t AdSumBuffer[ADC_BUF_SIZE];
static char     buffer[CMD_BUF_SIZE];

/* Writing integer scalars to elements of a file-scope static array */
void test_element_writes(void)
{
    uint8_t val = 42;
    dev_info[0] = val;        /* subscript write — not a pointer escape */
    dev_info[3] = val;
    dev_info[7] = 0xFF;

    uint16_t sample = 1234;
    for (int i = 0; i < ADC_BUF_SIZE; i++) {
        AdSumBuffer[i] = sample; /* subscript write — not a pointer escape */
    }

    buffer[0] = 'A';
    buffer[1] = '\0';
}

/* memcpy with global dest and local source: data copy, not pointer escape */
void test_memcpy_global_dest(void)
{
    char ver_str[32];
    ver_str[0] = '1'; ver_str[1] = '.'; ver_str[2] = '0'; ver_str[3] = '\0';
    memcpy(buffer, ver_str, sizeof(ver_str));   /* copies data, no pointer stored */
}
