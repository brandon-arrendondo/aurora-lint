#define PP_CAT(a, b) a##b
#define PP_HANDLER(n) PP_CAT(n, _handler)
#define PP_CALL_BAZ() PP_CAT(baz, _fn)()
