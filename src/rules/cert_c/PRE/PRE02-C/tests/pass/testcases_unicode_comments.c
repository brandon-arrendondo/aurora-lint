/*
 * Rule: PRE02-C
 * Source: testcases
 * Status: PASS - Should NOT trigger PRE02-C violation
 *
 * Regression test: PRE02-C checker must not panic when is_cast_with_parenthesized_operand
 * receives text containing multi-byte UTF-8 characters. The underlying bug was that
 * chars().enumerate() indices (character positions) were used as byte offsets for
 * string slicing, which panics when a multi-byte char falls between a matched
 * pattern and a delimiter.
 */

/* 宏（macro）定义：强制类型转换（cast）示例 */
#define SAFE_CAST(x) ((uint8_t)((x) & 0xFF))

/* 类型转换（type cast）加全括号表达式（parenthesized operand） */
#define SCALE(x) ((int)(x))

/* 正常的宏定义（normal macro）— 没有违规 */
#define DOUBLE(x) ((x) * 2)

/* 位操作（bitwise operation）宏，使用完整括号 */
#define MASK(x, m) ((x) & (m))

int foo(int a, int b)
{
    /* 局部变量（local variable）计算 */
    int r1 = SAFE_CAST(a);
    int r2 = SCALE(b);
    int r3 = DOUBLE(a + b);  /* 加法（addition）结果 */
    int r4 = MASK(a, 0xFF);
    return r1 + r2 + r3 + r4;
}
