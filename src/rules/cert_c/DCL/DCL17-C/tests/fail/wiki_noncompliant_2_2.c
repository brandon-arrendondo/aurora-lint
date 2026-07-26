/*
 * Rule: DCL17-C
 * Source: wiki
 * Status: FAIL - Should trigger DCL17-C violation
 */

foo:
  movl $0, y
  movl x, %eax
  jmp .L2
.L3:
  movl y, %eax
  incl %eax
  movl %eax, y
.L2:
  movl y, %eax
  cmpl $10, %eax
  jg .L3
  ret