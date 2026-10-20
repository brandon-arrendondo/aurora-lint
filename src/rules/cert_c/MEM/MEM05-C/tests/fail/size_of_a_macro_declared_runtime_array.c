/*
 * Rule: MEM05-C
 * Source: custom
 * Status: FAIL - Should trigger MEM05-C violation
 * Description: A VLA declared through a macro is a name the file's
 * declarations do not show, so an array sized by sizeof of it is not shown
 * to be fixed-size, whatever the name is spelled like: a name ending in
 * `_t` is not taken for a type on its spelling alone.
 */
#define VBUF(name, len) char name[len]

void macro_declared(int n) {
    VBUF(buf_t, n);
    char by_suffixed_name[sizeof(buf_t)];
    VBUF(bufx, n);
    char by_plain_name[sizeof(bufx)];
    (void)by_suffixed_name; (void)by_plain_name;
}
