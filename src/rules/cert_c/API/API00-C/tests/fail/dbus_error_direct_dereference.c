/*
 * Rule: API00-C
 * Source: custom
 * Status: FAIL - Should trigger API00-C violation
 * Description: Unlike the relay-only case (see pass/dbus_set_error_relay.c),
 * a DBusError* that is directly dereferenced (not merely forwarded to
 * dbus_set_error) still needs its own NULL check -- the null-accepting-sink
 * table must not suppress a genuine local dereference.
 */

typedef struct DBusError {
    const char *name;
    const char *message;
} DBusError;

void print_error_name(DBusError *error) {
    __builtin_printf("%s\n", error->name);
}
