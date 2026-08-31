/*
 * Rule: API00-C
 * Source: task_628
 * Status: PASS - Should NOT trigger API00-C violation
 */
// sqc-test: prescan

/*
 * Rule: API00-C - Functions should validate their parameters
 * Status: PASS
 * Reason: task 594 exempts a function reachable only through a
 * dispatch-table registration (never called directly by name anywhere in
 * the project) from API00-C's NULL-check requirement, since its contract
 * is established at registration, not by direct callers. hostap's D-Bus
 * method table registers each handler through a function-pointer cast --
 * `(WPADBusMethodHandler) wpas_dbus_handler_get_capabilities` -- rather
 * than a bare identifier. The prescan's dispatch-table-ref collector only
 * recognized a bare `identifier` inside the initializer list, so a
 * cast-wrapped registration was invisible and this whole hostap dbus
 * handler class kept getting validated as if directly reachable (task 628).
 */

typedef struct dbus_message DBusMessage;

typedef DBusMessage *(*WPADBusMethodHandler)(DBusMessage *message, void *priv);

struct dbus_method_desc {
    const char *name;
    WPADBusMethodHandler handler;
};

DBusMessage *wpas_dbus_handler_get_capabilities(DBusMessage *message, void *priv)
{
    /* No NULL check: this handler is only ever invoked by the dispatcher
     * below with a guaranteed non-NULL message, never called directly. */
    return message;
}

static const struct dbus_method_desc methods[] = {
    { "GetCapabilities", (WPADBusMethodHandler) wpas_dbus_handler_get_capabilities },
};

DBusMessage *dispatch(DBusMessage *message, void *priv)
{
    if (message == NULL) {
        return NULL;
    }
    return methods[0].handler(message, priv);
}
