#define module_init(function, type)                                    \
static void __attribute__((constructor)) do_init_ ## function(void)    \
{                                                                      \
    register_module_init(function, type);                              \
}
#define type_init(function) module_init(function, 1)
void register_module_init(void (*fn)(void), int type);
