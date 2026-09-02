/*
 * Rule: DCL13-C
 * Source: task 642 (hostap src/utils/edit.c:1113, gt_id 68453)
 * Status: PASS - Function-pointer-typed parameters are excluded; DCL13-C is
 * about pointers to data not changed by the function, not pointers to code.
 * const on a function-pointer type would qualify the pointer variable
 * itself, not the pointee, so it doesn't carry the rule's intended meaning
 * and isn't idiomatic C for callbacks.
 */

/* Simple function pointer parameter, never reassigned in the body */
void register_callback(void (*cb)(void *ctx, int result)) {
    cb(NULL, 0);
}

/* Function pointer parameter whose return type is itself a pointer,
 * mirroring hostap's edit_init(..., char **(*completion_cb)(...), ...) */
int edit_init(void (*cmd_cb)(void *ctx, char *cmd),
              void (*eof_cb)(void *ctx),
              char **(*completion_cb)(void *ctx, const char *cmd, int pos)) {
    cmd_cb(NULL, "x");
    eof_cb(NULL);
    completion_cb(NULL, "x", 0);
    return 0;
}

/* Array of function pointers */
void run_all(void (*handlers[])(int), int count) {
    for (int i = 0; i < count; i++) {
        handlers[i](i);
    }
}
