/*
 * Rule: ARR00-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR00-C violation
 *
 * Regression test: ARR00-C checker must not panic on source files that contain
 * multi-byte UTF-8 characters (e.g. Chinese full-width punctuation like （ ）
 * or other CJK characters) in comments or string literals.  The underlying bug
 * was that find_pointer_source_array_recursive used chars().enumerate() indices
 * (character positions) as byte offsets into the source string, which panics
 * whenever a multi-byte character appears between the matched pattern and a
 * stopping delimiter.
 */

#include <stddef.h>
#include <string.h>

/* 检查电流（checkcurrent）— verifies current within bounds */
static int checkcurrent(const int *buf, size_t len)
{
    /* 遍历缓冲区（buffer）内的每一个元素 */
    for (size_t i = 0; i < len; i++) {
        if (buf[i] < 0)
            return -1;
    }
    return 0;
}

/* Safe pointer arithmetic with Unicode in surrounding comments.
 * ptr（pointer）is advanced within the array bounds at all times. */
static void safe_advance(int arr[], int n)
{
    int *ptr = arr;          /* 指针（pointer）初始化 */
    int *end = arr + n;      /* 结束位置（end position） */

    while (ptr < end) {
        /* 对每个元素（element）执行操作 */
        *ptr = *ptr + 1;
        ptr++;
    }
}

/* Mixed ASCII/CJK identifiers in comments should not confuse the checker.
 * 函数（function）: copy_range — copies a sub-range of src into dst. */
static void copy_range(int *dst, const int *src, size_t count)
{
    /* 确保长度（length）不超过目标缓冲区 */
    memcpy(dst, src, count * sizeof(int));
}

int main(void)
{
    int data[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    int out[8]  = {0};

    checkcurrent(data, 8);
    safe_advance(data, 8);
    copy_range(out, data, 8);

    return 0;
}
