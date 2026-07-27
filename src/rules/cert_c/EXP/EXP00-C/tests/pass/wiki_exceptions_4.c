/*
 * Rule: EXP00-C
 * Source: wiki
 * Status: PASS - Should NOT trigger EXP00-C violation. EXP00-C-EX1:
 * mathematical expressions that follow standard algebraic precedence
 * (multiplication binds tighter than addition here) do not require
 * parentheses; adding them anyway is redundant but harmless, not a
 * violation. The wiki's generic "noncompliant" code-block styling was
 * scraped literally without this exception context (verified against
 * live wiki: "The expression with redundant parentheses is compliant").
 */

x + (y * z)