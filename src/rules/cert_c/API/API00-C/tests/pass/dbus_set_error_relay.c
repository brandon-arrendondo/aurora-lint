/*
 * Rule: API00-C
 * Source: custom
 * Status: PASS - Should NOT trigger API00-C violation
 * Description: A DBusError *error out-param whose only use is being relayed
 * to dbus_set_error/dbus_set_error_const is safe unvalidated -- both are
 * documented to silently ignore a NULL DBusError* (task 742, hostap's D-Bus
 * getter family).
 */

typedef struct DBusError {
    const char *name;
    const char *message;
} DBusError;

typedef int dbus_bool_t;

void dbus_set_error(DBusError *error, const char *name, const char *format, ...);
void dbus_set_error_const(DBusError *error, const char *name, const char *message);

dbus_bool_t get_prop(int type, DBusError *error) {
    if (type < 0) {
        dbus_set_error(error, "org.freedesktop.DBus.Error.Failed",
                       "bad type");
        return 0;
    }
    return 1;
}

dbus_bool_t set_prop(int value, DBusError *error) {
    if (value < 0) {
        dbus_set_error_const(error, "org.freedesktop.DBus.Error.InvalidArgs",
                             "invalid value");
        return 0;
    }
    return 1;
}
