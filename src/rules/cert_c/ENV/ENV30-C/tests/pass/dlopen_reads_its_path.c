/*
 * Rule: ENV30-C
 * Source: real-world
 * Status: PASS - Should NOT trigger ENV30-C violation
 */

/*
 * dlopen's first parameter is `const char *filename`: it reads the path
 * and never writes through it, so handing it a string that came from
 * getenv modifies nothing. lua's lua_initreadline is the shape.
 */

#include <dlfcn.h>
#include <stdlib.h>

void load_library_from_environment(void) {
    const char *library = getenv("MYAPP_READLINE_LIB");

    if (library == NULL) {
        library = "libreadline.so";
    }

    /* COMPLIANT: dlopen reads the path string it is given */
    void *handle = dlopen(library, RTLD_NOW | RTLD_LOCAL);

    if (handle != NULL) {
        dlclose(handle);
    }
}
