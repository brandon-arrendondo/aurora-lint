/*
 * Rule: MSC13-C
 * Status: PASS - a `case` label with no braces around its body does NOT open
 * a scope: the declaration belongs to the switch's own block, exactly as if
 * the label were not there, and a read further down the same arm resolves
 * back to it. tree-sitter-c still nests those statements under a
 * `case_statement` node, so a scope search that only looked at the
 * compound_statement's literal children found no declaration and reported
 * every such variable unused (task 756, raylib
 * src/platforms/rcore_desktop_rgfw.c: `int button` / `int pressed` under
 * `case GAMEPAD_AXIS_LEFT_TRIGGER:`, `int axisCount` under
 * `case MG_EVENT_GAMEPAD_CONNECT:`).
 *
 * The braced arm below is the control: it was never flagged, which is what
 * localized the bug to the unbraced case.
 */

void sink(int);

void f(int axis)
{
    switch (axis) {
        case 1:
            sink(axis);
            int button = axis + 1;
            int pressed = (axis > 0);
            sink(button);
            sink(pressed);
            break;
        case 2:
        {
            int braced = axis + 2;
            sink(braced);
        } break;
        case 3:
        case 4:
            /* fall-through label chain: still one scope */
            sink(axis);
            int shared = axis * 2;
            sink(shared);
            break;
        default:
            break;
    }
}
