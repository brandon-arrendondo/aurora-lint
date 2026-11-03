/*
 * Rule: DCL40-C
 * Source: regression
 * Status: PASS - a void definition behind a section macro and before a
 * visibility macro keeps its return type
 *
 * `BOOT_CODE` (a section attribute) and `VISIBLE` (a visibility
 * attribute) come from a configuration header this file does not define.
 * The parser read `BOOT_CODE` as the type, stranded `void`, and took
 * `VISIBLE` for the return type of `arm_errata`, which then disagreed
 * with its prototype and looked like a non-void function with no return.
 * Both definitions open with `BOOT_CODE`, which is blanked in one pass.
 */
void arm_errata(void);

BOOT_CODE static void disable_loop_buffer(void)
{
}

BOOT_CODE void VISIBLE arm_errata(void)
{
    disable_loop_buffer();
}
