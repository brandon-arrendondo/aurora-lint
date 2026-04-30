/*
 * Rule: ARR38-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR38-C violation
 *
 * Regression test: ARR38-C checker must not misidentify operators or panic
 * when extract_simple_assignment processes text near multi-byte UTF-8 characters.
 * The underlying bug was that text.find('=') returns a byte offset but
 * text.chars().nth(byte_offset) counts characters, producing the wrong char
 * when multi-byte characters precede the '=' sign.
 */

#include <string.h>

/* 字符串（string）复制 — 使用 sizeof 目标缓冲区（destination buffer） */
int main(void)
{
    char src[32] = "hello";  /* 源缓冲区（source buffer） */
    char dst[32] = {0};      /* 目标缓冲区（destination buffer） */

    /* sizeof(dst) 确保不超出边界（bounds） */
    memcpy(dst, src, sizeof(dst));

    return 0;
}
