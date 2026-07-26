/*
 * Rule: MSC12-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC12-C violation
 */

if (param == 1)
   openWindow();
 else if (param == 2)
   closeWindow();
 else if (param == 1) /* Duplicated condition */
   moveWindowToTheBackground();