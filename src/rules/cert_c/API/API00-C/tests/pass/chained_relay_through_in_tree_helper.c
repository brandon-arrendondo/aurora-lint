/*
 * Rule: API00-C
 * Source: real-world (task 759)
 * Status: PASS - Should NOT trigger API00-C violation
 * Description: hostap's D-Bus getters relay their `DBusError *error` not
 * directly to dbus_set_error(_const) but to an in-tree helper first
 * (wpa_dbus_dict_open_read), which is ITSELF relay-only for error. The old
 * relay check trusted a callee only through a fixed external table or an
 * explicit `if (!param)` guard, and this helper has neither -- it does not
 * check error, it relays it -- so every caller stayed unsuppressed even
 * though the whole chain is safe.
 */

typedef struct DBusError {
    const char *name;
} DBusError;

typedef struct DBusMessageIter {
    int pos;
} DBusMessageIter;

void dbus_set_error_const(DBusError *error, const char *name, const char *message);

int wpa_dbus_dict_open_read(DBusMessageIter *iter, DBusMessageIter *iter_dict,
                            DBusError *error)
{
    if (iter == 0 || iter_dict == 0) {
        dbus_set_error_const(error, "org.freedesktop.DBus.Error.Failed",
                             "invalid iterator");
        return 0;
    }
    iter_dict->pos = iter->pos;
    return 1;
}

int wpas_dbus_setter_global_wfd_ies(DBusMessageIter *iter, DBusError *error)
{
    DBusMessageIter iter_dict;

    if (iter == 0)
        return 0;
    return wpa_dbus_dict_open_read(iter, &iter_dict, error);
}
