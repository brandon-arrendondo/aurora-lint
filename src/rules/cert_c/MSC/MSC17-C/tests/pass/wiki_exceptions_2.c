/*
 * Rule: MSC17-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

enum WidgetEnum { WE_W, WE_X, WE_Y, WE_Z } widget_type;
widget_type = WE_X;

switch (widget_type) {
  case WE_W:
    /* ... */
    /* No break; fall through to the WE_X case */
  case WE_X:
    /* ... */
    break;
  case WE_Y: case WE_Z:
    /* ... */
    break;
  default: /* Can't happen */
     /* Handle error condition */
}