/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: PASS - a macro from a header the scan cannot see pastes the static's name from its argument
 */
#include <glib-object.h>

G_DEFINE_TYPE(Foo, foo, G_TYPE_OBJECT)

static void foo_class_init(FooClass *klass)
{
    (void)klass;
}

static void foo_init(Foo *self)
{
    (void)self;
}

GType foo_get_type_wrapper(void)
{
    return foo_get_type();
}
